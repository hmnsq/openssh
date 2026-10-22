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
#define	رقم_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#define X11_BASE_PORT	6000
/* Maximum number of fake X11 displays to try. */
#define MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
تعریفنوع تهی chan_fn(ساختار ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
ساختار permission {
	نویسه *host_to_connect;		/* Connect to 'host'. */
	صحیح port_to_connect;		/* Connect to 'port'. */
	نویسه *listen_host;		/* Remote side should listen address. */
	نویسه *listen_path;		/* Remote side should listen path. */
	صحیح listen_port;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
ساختار channel_connect {
	نویسه *host;
	صحیح port;
	ساختار addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
ساختار permission_set {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int رقم_permitted_user;
	ساختار permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int رقم_permitted_admin;
	ساختار permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	صحیح all_permitted;
};

/* Used to record timeouts per channel type */
ساختار ssh_channel_timeout {
	نویسه *type_pattern;
	دوگانه timeout_secs;
};

/* Master structure for channels state */
ساختار ssh_channels {
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
	ساختار permission_set local_perms;
	ساختار permission_set remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	نویسه *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	نویسه *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	نویسه *x11_saved_data;
	u_int x11_saved_data_len;

	/* Deadline after which all X11 connections are refused */
	دوگانه x11_refuse_time;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_data;
	u_int x11_fake_data_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	صحیح IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	صحیح want_tcp_keepalive;

	/* Channel timeouts by type */
	ساختار ssh_channel_timeout *timeouts;
	size_t ntimeouts;
	/* Global timeout for all OPEN channels */
	دوگانه global_deadline;
	دوگانه lastused;
	/* pattern-lists used to classify channels as bulk */
	نویسه *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
ایستا تهی port_open_helper(ساختار ssh *ssh, Channel *c, نویسه *rtype);
ایستا ثابت نویسه *channel_rfwd_bind_host(ثابت نویسه *listen_host);

/* non-blocking connect helpers */
ایستا صحیح connect_next(ساختار ssh *, ساختار channel_connect *);
ایستا Channel *rdynamic_connect_prepare(ساختار ssh *, نویسه *, نویسه *);
ایستا صحیح rdynamic_connect_finish(ساختار ssh *, Channel *);

/* Setup helper */
ایستا تهی channel_handler_init(ساختار ssh_channels *sc);

/* -- channel core */

تهی
channel_init_channels(ساختار ssh *ssh)
{
	ساختار ssh_channels *sc;

	اگر ((sc = calloc(1, اندازه(*sc))) == پوچ)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, اندازه(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(ساختار ssh *ssh, صحیح id)
{
	Channel *c;

	اگر (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		بازگشت پوچ;
	}
	c = ssh->chanctxt->channels[id];
	اگر (c == پوچ) {
		logit_f("%d: bad id: channel free", id);
		بازگشت پوچ;
	}
	بازگشت c;
}

Channel *
channel_by_remote_id(ساختار ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	برای (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c != پوچ && c->have_remote_id && c->remote_id == remote_id)
			بازگشت c;
	}
	بازگشت پوچ;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(ساختار ssh *ssh, صحیح id)
{
	Channel *c;

	اگر ((c = channel_by_id(ssh, id)) == پوچ)
		بازگشت پوچ;

	انتخاب (c->type) {
	حالت SSH_CHANNEL_X11_OPEN:
	حالت SSH_CHANNEL_LARVAL:
	حالت SSH_CHANNEL_CONNECTING:
	حالت SSH_CHANNEL_DYNAMIC:
	حالت SSH_CHANNEL_RDYNAMIC_OPEN:
	حالت SSH_CHANNEL_RDYNAMIC_FINISH:
	حالت SSH_CHANNEL_OPENING:
	حالت SSH_CHANNEL_OPEN:
	حالت SSH_CHANNEL_ABANDONED:
	حالت SSH_CHANNEL_MUX_PROXY:
		بازگشت c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	بازگشت پوچ;
}

ایستا تهی
free_connect_ctx(ساختار channel_connect *cctx)
{
	آزاد(cctx->host);
	اگر (cctx->aitop) {
		اگر (cctx->aitop->ai_family == AF_UNIX)
			آزاد(cctx->aitop);
		وگرنه
			freeaddrinfo(cctx->aitop);
	}
	memset(cctx, 0, اندازه(*cctx));
}

ایستا تهی
channel_free_connect_ctx(Channel *c)
{
	اگر (c == پوچ || c->connect_ctx == پوچ)
		بازگشت;
	free_connect_ctx(c->connect_ctx);
	آزاد(c->connect_ctx);
	c->connect_ctx = پوچ;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
تهی
channel_set_tcp_keepalives(ساختار ssh *ssh, صحیح on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
تهی
channel_add_timeout(ساختار ssh *ssh, ثابت نویسه *type_pattern,
    دوگانه timeout_secs)
{
	ساختار ssh_channels *sc = ssh->chanctxt;

	اگر (strcmp(type_pattern, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		بازگشت;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_pattern, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, اندازه(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_pattern = xstrdup(type_pattern);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
تهی
channel_clear_timeouts(ساختار ssh *ssh)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	size_t i;

	debug3_f("clearing");
	برای (i = 0; i < sc->ntimeouts; i++)
		آزاد(sc->timeouts[i].type_pattern);
	آزاد(sc->timeouts);
	sc->timeouts = پوچ;
	sc->ntimeouts = 0;
}

ایستا دوگانه
lookup_timeout(ساختار ssh *ssh, ثابت نویسه *type)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	size_t i;

	برای (i = 0; i < sc->ntimeouts; i++) {
		اگر (match_pattern(type, sc->timeouts[i].type_pattern))
			بازگشت sc->timeouts[i].timeout_secs;
	}

	بازگشت 0;
}

ایستا تهی
channel_classify(ساختار ssh *ssh, Channel *c)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	ثابت نویسه *type = c->xctype == پوچ ? c->ctype : c->xctype;
	ثابت صحیح has_tty = c->isatty || c->remote_has_tty;
	ثابت نویسه *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != پوچ && match_pattern_list(type, classifier, 0) == 1;
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
تهی
channel_set_xtype(ساختار ssh *ssh, صحیح id, ثابت نویسه *xctype)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	اگر ((c = channel_by_id(ssh, id)) == پوچ)
		fatal_f("missing channel %d", id);
	اگر (c->xctype != پوچ)
		آزاد(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	دوگانه xtype_deadline = lookup_timeout(ssh, c->xctype);
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
ایستا تهی
channel_set_used_time(ساختار ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	اگر (c != پوچ)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
ایستا دوگانه
channel_get_expiry(ساختار ssh *ssh, Channel *c)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	دوگانه expiry = 0, channel_expiry;

	اگر (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	اگر (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		اگر (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	بازگشت expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
صحیح
channel_has_bulk(ساختار ssh *ssh)
{
	بازگشت ssh->chanctxt != پوچ && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
ایستا تهی
channel_register_fds(ساختار ssh *ssh, Channel *c, صحیح rfd, صحیح wfd, صحیح efd,
    صحیح extusage, صحیح nonblock, صحیح is_tty)
{
	صحیح val;

	اگر (rfd != -1)
		(تهی)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	اگر (wfd != -1 && wfd != rfd)
		(تهی)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	اگر (efd != -1 && efd != rfd && efd != wfd)
		(تهی)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	اگر ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#endif

	/* enable nonblocking mode */
	c->restore_block = 0;
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
			c->restore_block |= CHANNEL_RESTORE_RFD;
			set_nonblock(rfd);
		}
		اگر (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_block |= CHANNEL_RESTORE_WFD;
			set_nonblock(wfd);
		}
		اگر (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_block |= CHANNEL_RESTORE_EFD;
			set_nonblock(efd);
		}
	} وگرنه اگر (nonblock) {
		اگر (rfd != -1)
			set_nonblock(rfd);
		اگر (wfd != -1)
			set_nonblock(wfd);
		اگر (efd != -1)
			set_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_set_used_time(ssh, پوچ);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(ساختار ssh *ssh, نویسه *ctype, صحیح type, صحیح rfd, صحیح wfd, صحیح efd,
    u_int window, u_int maxpack, صحیح extusage, ثابت نویسه *remote_name,
    صحیح nonblock)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	u_int i, found = 0;
	Channel *c;
	صحیح r;

	/* Try to find a free slot where to put the new channel. */
	برای (i = 0; i < sc->channels_alloc; i++) {
		اگر (sc->channels[i] == پوچ) {
			/* Found a free slot. */
			found = i;
			بشکن;
		}
	}
	اگر (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		found = sc->channels_alloc;
		اگر (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, اندازه(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[found] = xcalloc(1, اندازه(Channel));
	اگر ((c->درون_داد = sshbuf_new()) == پوچ ||
	    (c->output = sshbuf_new()) == پوچ ||
	    (c->extended = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_set_max_size(c->درون_داد, CHAN_درون_داد_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_درون_داد_OPEN;
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
	بازگشت c;
}

تهی
channel_set_tty(ساختار ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

صحیح
channel_close_fd(ساختار ssh *ssh, Channel *c, صحیح *fdp)
{
	صحیح ret, fd = *fdp;

	اگر (fd == -1)
		بازگشت 0;

	/* restore blocking */
	اگر (*fdp == c->rfd &&
	    (c->restore_block & CHANNEL_RESTORE_RFD) != 0)
		(تهی)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	وگرنه اگر (*fdp == c->wfd &&
	    (c->restore_block & CHANNEL_RESTORE_WFD) != 0)
		(تهی)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	وگرنه اگر (*fdp == c->efd &&
	    (c->restore_block & CHANNEL_RESTORE_EFD) != 0)
		(تهی)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

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
	بازگشت ret;
}

/* Close all channel fd/socket. */
ایستا تهی
channel_close_fds(ساختار ssh *ssh, Channel *c)
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

ایستا تهی
fwd_perm_clear(ساختار permission *perm)
{
	آزاد(perm->host_to_connect);
	آزاد(perm->listen_host);
	آزاد(perm->listen_path);
	memset(perm, 0, اندازه(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
ایستا ثابت نویسه *
fwd_ident(صحیح who, صحیح where)
{
	اگر (who == FORWARD_ADM) {
		اگر (where == FORWARD_LOCAL)
			بازگشت "admin local";
		وگرنه اگر (where == FORWARD_REMOTE)
			بازگشت "admin remote";
	} وگرنه اگر (who == FORWARD_USER) {
		اگر (where == FORWARD_LOCAL)
			بازگشت "user local";
		وگرنه اگر (where == FORWARD_REMOTE)
			بازگشت "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
ایستا ساختار permission_set *
permission_set_get(ساختار ssh *ssh, صحیح where)
{
	ساختار ssh_channels *sc = ssh->chanctxt;

	انتخاب (where) {
	حالت FORWARD_LOCAL:
		بازگشت &sc->local_perms;
		بشکن;
	حالت FORWARD_REMOTE:
		بازگشت &sc->remote_perms;
		بشکن;
	پیشفرض:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
ایستا تهی
permission_set_get_array(ساختار ssh *ssh, صحیح who, صحیح where,
    ساختار permission ***permpp, u_int **npermpp)
{
	ساختار permission_set *pset = permission_set_get(ssh, where);

	انتخاب (who) {
	حالت FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->رقم_permitted_user;
		بشکن;
	حالت FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->رقم_permitted_admin;
		بشکن;
	پیشفرض:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
ایستا صحیح
permission_set_add(ساختار ssh *ssh, صحیح who, صحیح where,
    ثابت نویسه *host_to_connect, صحیح port_to_connect,
    ثابت نویسه *listen_host, ثابت نویسه *listen_path, صحیح listen_port,
    Channel *downstream)
{
	ساختار permission **permp;
	u_int n, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);

	اگر (*npermp >= INT_MAX)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, اندازه(**permp));
	n = (*npermp)++;
#define MAYBE_DUP(s) ((s == پوچ) ? پوچ : xstrdup(s))
	(*permp)[n].host_to_connect = MAYBE_DUP(host_to_connect);
	(*permp)[n].port_to_connect = port_to_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_path = MAYBE_DUP(listen_path);
	(*permp)[n].listen_port = listen_port;
	(*permp)[n].downstream = downstream;
#undef MAYBE_DUP
	بازگشت (صحیح)n;
}

ایستا تهی
mux_remove_remote_forwardings(ساختار ssh *ssh, Channel *c)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	ساختار permission_set *pset = &sc->local_perms;
	ساختار permission *perm;
	صحیح r;
	u_int i;

	برای (i = 0; i < pset->رقم_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		اگر (perm->downstream != c)
			ادامه;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_port);
		اگر ((r = sshpkt_start(ssh, SSH2_پیام_GLOBAL_REQUEST)) != 0 ||
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
تهی
channel_free(ساختار ssh *ssh, Channel *c)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	نویسه *s;
	u_int i, n;
	Channel *other;
	ساختار channel_confirm *cc;

	برای (n = 0, i = 0; i < sc->channels_alloc; i++) {
		اگر ((other = sc->channels[i]) == پوچ)
			ادامه;
		n++;
		/* detach from mux client and prepare for closing */
		اگر (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = پوچ;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_درون_داد_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	اگر (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		آزاد(c->mux_ctx);
		c->mux_ctx = پوچ;
	} وگرنه اگر (c->type == SSH_CHANNEL_MUX_LISTENER) {
		آزاد(c->mux_ctx);
		c->mux_ctx = پوچ;
	}

	اگر (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_message(ssh);
		debug3("channel %d: status: %s", c->self, s);
		آزاد(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->درون_داد);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->درون_داد = c->output = c->extended = پوچ;
	آزاد(c->remote_name);
	c->remote_name = پوچ;
	آزاد(c->path);
	c->path = پوچ;
	آزاد(c->listening_addr);
	c->listening_addr = پوچ;
	آزاد(c->xctype);
	c->xctype = پوچ;
	channel_free_connect_ctx(c);
	وقتی ((cc = TAILQ_FIRST(&c->status_confirms)) != پوچ) {
		اگر (cc->abandon_cb != پوچ)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->status_confirms, cc, entry);
		freezero(cc, اندازه(*cc));
	}
	اگر (c->filter_cleanup != پوچ && c->filter_ctx != پوچ)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = پوچ;
	freezero(c, اندازه(*c));
}

تهی
channel_free_all(ساختار ssh *ssh)
{
	u_int i;
	ساختار ssh_channels *sc = ssh->chanctxt;

	برای (i = 0; i < sc->channels_alloc; i++)
		اگر (sc->channels[i] != پوچ)
			channel_free(ssh, sc->channels[i]);

	آزاد(sc->channels);
	sc->channels = پوچ;
	sc->channels_alloc = 0;

	آزاد(sc->x11_saved_display);
	sc->x11_saved_display = پوچ;

	آزاد(sc->x11_saved_proto);
	sc->x11_saved_proto = پوچ;

	آزاد(sc->x11_saved_data);
	sc->x11_saved_data = پوچ;
	sc->x11_saved_data_len = 0;

	آزاد(sc->x11_fake_data);
	sc->x11_fake_data = پوچ;
	sc->x11_fake_data_len = 0;
}

تهی
channel_free_channels(ساختار ssh *ssh)
{
	ساختار ssh_channels *sc;

	اگر (ssh == پوچ || ssh->chanctxt == پوچ)
		بازگشت;
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
	freezero(sc, اندازه(*sc));
	ssh->chanctxt = پوچ;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
تهی
channel_close_all(ساختار ssh *ssh)
{
	u_int i;

	برای (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		اگر (ssh->chanctxt->channels[i] != پوچ)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
تهی
channel_stop_listening(ساختار ssh *ssh)
{
	u_int i;
	Channel *c;

	برای (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c != پوچ) {
			انتخاب (c->type) {
			حالت SSH_CHANNEL_AUTH_SOCKET:
			حالت SSH_CHANNEL_PORT_LISTENER:
			حالت SSH_CHANNEL_RPORT_LISTENER:
			حالت SSH_CHANNEL_X11_LISTENER:
			حالت SSH_CHANNEL_UNIX_LISTENER:
			حالت SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				بشکن;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
صحیح
channel_not_very_much_buffered_data(ساختار ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	برای (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c == پوچ || c->type != SSH_CHANNEL_OPEN)
			ادامه;
		اگر (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			بازگشت 0;
		}
	}
	بازگشت 1;
}

/* Returns true if any channel is still open. */
صحیح
channel_still_open(ساختار ssh *ssh)
{
	u_int i;
	Channel *c;

	برای (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c == پوچ)
			ادامه;
		انتخاب (c->type) {
		حالت SSH_CHANNEL_X11_LISTENER:
		حالت SSH_CHANNEL_PORT_LISTENER:
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
			ادامه;
		حالت SSH_CHANNEL_LARVAL:
			ادامه;
		حالت SSH_CHANNEL_OPENING:
		حالت SSH_CHANNEL_OPEN:
		حالت SSH_CHANNEL_RDYNAMIC_FINISH:
		حالت SSH_CHANNEL_X11_OPEN:
		حالت SSH_CHANNEL_MUX_CLIENT:
		حالت SSH_CHANNEL_MUX_PROXY:
			بازگشت 1;
		پیشفرض:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	بازگشت 0;
}

/* Returns true if a channel with a TTY is open. */
صحیح
channel_tty_open(ساختار ssh *ssh)
{
	u_int i;
	Channel *c;

	برای (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c == پوچ || c->type != SSH_CHANNEL_OPEN)
			ادامه;
		اگر (c->client_tty)
			بازگشت 1;
	}
	بازگشت 0;
}

/* Returns the id of an open channel suitable for keepaliving */
صحیح
channel_find_open(ساختار ssh *ssh)
{
	u_int i;
	Channel *c;

	برای (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c == پوچ || !c->have_remote_id)
			ادامه;
		انتخاب (c->type) {
		حالت SSH_CHANNEL_CLOSED:
		حالت SSH_CHANNEL_DYNAMIC:
		حالت SSH_CHANNEL_RDYNAMIC_OPEN:
		حالت SSH_CHANNEL_RDYNAMIC_FINISH:
		حالت SSH_CHANNEL_X11_LISTENER:
		حالت SSH_CHANNEL_PORT_LISTENER:
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
			ادامه;
		حالت SSH_CHANNEL_LARVAL:
		حالت SSH_CHANNEL_AUTH_SOCKET:
		حالت SSH_CHANNEL_OPEN:
		حالت SSH_CHANNEL_X11_OPEN:
			بازگشت i;
		پیشفرض:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	بازگشت -1;
}

/* Returns the state of the channel's extended usage flag */
ثابت نویسه *
channel_format_extended_usage(ثابت Channel *c)
{
	اگر (c->efd == -1)
		بازگشت "closed";

	انتخاب (c->extended_usage) {
	حالت CHAN_EXTENDED_WRITE:
		بازگشت "write";
	حالت CHAN_EXTENDED_READ:
		بازگشت "read";
	حالت CHAN_EXTENDED_IGNORE:
		بازگشت "ignore";
	پیشفرض:
		بازگشت "UNKNOWN";
	}
}

ایستا نویسه *
channel_format_status(ثابت Channel *c)
{
	نویسه *ret = پوچ;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != پوچ ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != پوچ ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->درون_داد),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_child_id ? "c" : "nc", c->ctl_child_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	بازگشت ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
نویسه *
channel_open_message(ساختار ssh *ssh)
{
	ساختار sshbuf *buf;
	Channel *c;
	u_int i;
	صحیح r;
	نویسه *cp, *ret;

	اگر ((buf = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	برای (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c == پوچ)
			ادامه;
		انتخاب (c->type) {
		حالت SSH_CHANNEL_X11_LISTENER:
		حالت SSH_CHANNEL_PORT_LISTENER:
		حالت SSH_CHANNEL_RPORT_LISTENER:
		حالت SSH_CHANNEL_CLOSED:
		حالت SSH_CHANNEL_AUTH_SOCKET:
		حالت SSH_CHANNEL_ZOMBIE:
		حالت SSH_CHANNEL_ABANDONED:
		حالت SSH_CHANNEL_MUX_LISTENER:
		حالت SSH_CHANNEL_UNIX_LISTENER:
		حالت SSH_CHANNEL_RUNIX_LISTENER:
			ادامه;
		حالت SSH_CHANNEL_LARVAL:
		حالت SSH_CHANNEL_OPENING:
		حالت SSH_CHANNEL_CONNECTING:
		حالت SSH_CHANNEL_DYNAMIC:
		حالت SSH_CHANNEL_RDYNAMIC_OPEN:
		حالت SSH_CHANNEL_RDYNAMIC_FINISH:
		حالت SSH_CHANNEL_OPEN:
		حالت SSH_CHANNEL_X11_OPEN:
		حالت SSH_CHANNEL_MUX_PROXY:
		حالت SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_status(c);
			اگر ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				آزاد(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			آزاد(cp);
			ادامه;
		پیشفرض:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	اگر ((ret = sshbuf_dup_string(buf)) == پوچ)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	بازگشت ret;
}

تهی
channel_report_open(ساختار ssh *ssh, صحیح level)
{
	نویسه *open, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, اندازه(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (long)getpid());
	open = oopen = channel_open_message(ssh);
	وقتی ((cp = strsep(&open, "\r\n")) != پوچ) {
		اگر (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	آزاد(oopen);
}

ایستا تهی
open_preamble(ساختار ssh *ssh, ثابت نویسه *where, Channel *c, ثابت نویسه *type)
{
	صحیح r;

	اگر ((r = sshpkt_start(ssh, SSH2_پیام_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

تهی
channel_send_open(ساختار ssh *ssh, صحیح id)
{
	Channel *c = channel_lookup(ssh, id);
	صحیح r;

	اگر (c == پوچ) {
		logit("channel_send_open: %d: bad id", id);
		بازگشت;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	اگر ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

تهی
channel_request_start(ساختار ssh *ssh, صحیح id, ثابت نویسه *service,
    صحیح wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	صحیح r;

	اگر (c == پوچ) {
		logit_f("%d: unknown channel id", id);
		بازگشت;
	}
	اگر (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

تهی
channel_register_status_confirm(ساختار ssh *ssh, صحیح id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, تهی *ctx)
{
	ساختار channel_confirm *cc;
	Channel *c;

	اگر ((c = channel_lookup(ssh, id)) == پوچ)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, اندازه(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->status_confirms, cc, entry);
}

تهی
channel_register_open_confirm(ساختار ssh *ssh, صحیح id,
    channel_open_fn *fn, تهی *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	اگر (c == پوچ) {
		logit_f("%d: bad id", id);
		بازگشت;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

تهی
channel_register_cleanup(ساختار ssh *ssh, صحیح id,
    channel_callback_fn *fn, صحیح do_close)
{
	Channel *c = channel_by_id(ssh, id);

	اگر (c == پوچ) {
		logit_f("%d: bad id", id);
		بازگشت;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

تهی
channel_cancel_cleanup(ساختار ssh *ssh, صحیح id)
{
	Channel *c = channel_by_id(ssh, id);

	اگر (c == پوچ) {
		logit_f("%d: bad id", id);
		بازگشت;
	}
	c->detach_user = پوچ;
	c->detach_close = 0;
}

تهی
channel_register_filter(ساختار ssh *ssh, صحیح id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, تهی *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	اگر (c == پوچ) {
		logit_f("%d: bad id", id);
		بازگشت;
	}
	c->درون_داد_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

تهی
channel_set_fds(ساختار ssh *ssh, صحیح id, صحیح rfd, صحیح wfd, صحیح efd,
    صحیح extusage, صحیح nonblock, صحیح is_tty, u_int window_max)
{
	Channel *c = channel_lookup(ssh, id);
	صحیح r;

	اگر (c == پوچ || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	اگر (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_register_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_set_used_time(ssh, c);
	c->local_window = c->local_window_max = window_max;

	اگر ((r = sshpkt_start(ssh, SSH2_پیام_CHANNEL_WINDOW_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ایستا تهی
channel_pre_listener(ساختار ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

ایستا تهی
channel_pre_connecting(ساختار ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

ایستا تهی
channel_pre_open(ساختار ssh *ssh, Channel *c)
{
	c->io_want = 0;
	اگر (c->istate == CHAN_درون_داد_OPEN &&
	    c->remote_window > 0 &&
	    sshbuf_len(c->درون_داد) < c->remote_window &&
	    sshbuf_check_reserve(c->درون_داد, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	اگر (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		اگر (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} وگرنه اگر (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			اگر (CHANNEL_EFD_OUTPUT_ACTIVE(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			وگرنه
				chan_obuf_empty(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	اگر (c->efd != -1 && !(c->istate == CHAN_درون_داد_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		اگر (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		وگرنه اگر (c->efd != -1 && !(c->flags & CHAN_EOF_SENT) &&
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
ایستا صحیح
x11_open_helper(ساختار ssh *ssh, ساختار sshbuf *b)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, data_len;

	اگر (sc->x11_saved_proto == پوچ) {
		error("X11 forwarding opened before X11 forwarding requested");
		بازگشت -1;
	}

	/* Is this being called after the refusal deadline? */
	اگر (sc->x11_refuse_time != 0.0 &&
	    monotime_double() >= sc->x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		بازگشت -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	اگر (sshbuf_len(b) < 12)
		بازگشت 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	اگر (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		data_len = 256 * ucp[8] + ucp[9];
	} وگرنه اگر (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		data_len = ucp[8] + 256 * ucp[9];
	} وگرنه {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		بازگشت -1;
	}

	/* Check if the whole packet is in buffer. */
	اگر (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((data_len + 3) & ~3))
		بازگشت 0;

	/* Check if authentication protocol matches. */
	اگر (proto_len != strlen(sc->x11_saved_proto) ||
	    memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		بازگشت -1;
	}
	/* Check if authentication data matches our fake data. */
	اگر (data_len != sc->x11_fake_data_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_data, sc->x11_fake_data_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		بازگشت -1;
	}
	/* Check fake data length */
	اگر (sc->x11_fake_data_len != sc->x11_saved_data_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_data_len, sc->x11_saved_data_len);
		بازگشت -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	memcpy(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_data, sc->x11_saved_data_len);
	بازگشت 1;
}

تهی
channel_force_close(ساختار ssh *ssh, Channel *c, صحیح abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	اگر (c->istate == CHAN_درون_داد_OPEN)
		chan_read_failed(ssh, c);
	اگر (c->istate == CHAN_درون_داد_WAIT_DRAIN) {
		sshbuf_reset(c->درون_داد);
		chan_ibuf_empty(ssh, c);
	}
	اگر (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	اگر (c->detach_user)
		c->detach_user(ssh, c->self, 1, پوچ);
	اگر (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	اگر (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

ایستا تهی
channel_pre_x11_open(ساختار ssh *ssh, Channel *c)
{
	صحیح ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	اگر (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		channel_pre_open(ssh, c);
	} وگرنه اگر (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

ایستا تهی
channel_pre_mux_client(ساختار ssh *ssh, Channel *c)
{
	c->io_want = 0;
	اگر (c->istate == CHAN_درون_داد_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->درون_داد, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	اگر (c->istate == CHAN_درون_داد_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->درون_داد);
		chan_ibuf_empty(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	اگر (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		اگر (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		وگرنه اگر (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_empty(ssh, c);
	}
}

ایستا درونخطی صحیح
socks_decode_error(Channel *c, صحیح status, ثابت نویسه *func, ثابت نویسه *پیام)
{
	اگر (status == SSH_ERR_MESSAGE_INCOMPLETE)
		بازگشت 0;
	وگرنه {
		debug_r(status, "%s: channel %d: decode %s",
		    func, c->self, پیام);
		بازگشت -1;
	}
}

/* try to decode a socks4 header */
ایستا صحیح
channel_decode_socks4(Channel *c, ساختار sshbuf *درون_داد, ساختار sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_port;
	نویسه *user = پوچ, *host = پوچ;
	صحیح success = -1, socks4a = 0, r;
	ساختار sshbuf *b = پوچ;

	اگر (sshbuf_len(درون_داد) < 9)
		بازگشت 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	اگر ((b = sshbuf_fromb(درون_داد)) == پوچ)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	اگر ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, اندازه(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, پوچ)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		برو out;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	اگر (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		اگر ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, پوچ)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			برو out;
		}
		socks4a = 1;
	} وگرنه {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	اگر ((r = sshbuf_consume_upto_child(درون_داد, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (صحیح)socks_cmd,
	    host, dest_port);
	اگر (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		برو out;
	}
	آزاد(c->path);
	c->path = host;
	host = پوچ; /* transferred */
	c->host_port = dest_port;

	/* Reply to the SOCKS4 client */
	اگر ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
	    (r = sshbuf_put_u8(output, 90)) != 0 ||	/* cd: req granted */
	    (r = sshbuf_put_u16(output, 0)) != 0 ||	/* port: ignored */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0) /* ignored */
		fatal_fr(r, "channel %d: compose reply", c->self);

	/* success */
	success = 1;
 out:
	sshbuf_free(b);
	آزاد(user);
	آزاد(host);
	بازگشت success;
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
ایستا صحیح
channel_socks5_check_auth(Channel *c, ساختار sshbuf *b, ساختار sshbuf *درون_داد,
    ساختار sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, method;
	صحیح r;
	u_int i, found;

	/* format: ver | nmethods | methods */
	اگر ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		بازگشت socks_decode_error(c, r, __func__, "version");
	اگر (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	اگر ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		بازگشت socks_decode_error(c, r, __func__, "methods");
	برای (found = i = 0; i < nmethods; i++) {
		اگر ((r = sshbuf_get_u8(b, &method)) != 0)
			بازگشت socks_decode_error(c, r, __func__, "method");
		اگر (method == SSH_SOCKS5_NOAUTH)
			found = 1;
	}
	اگر (!found) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		بازگشت -1;
	}
	/* Consume completed request */
	اگر ((r = sshbuf_consume_upto_child(درون_داد, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	اگر ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	بازگشت 1;
}

ایستا صحیح
channel_decode_socks5(Channel *c, ساختار sshbuf *درون_داد, ساختار sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_port;
	نویسه dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	صحیح r, success = -1;;
	ساختار sshbuf *b = پوچ;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	اگر ((b = sshbuf_fromb(درون_داد)) == پوچ)
		fatal_f("sshbuf_fromb failed");

	اگر (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		اگر ((r = channel_socks5_check_auth(c, b, درون_داد, output)) != 1) {
			success = r;
			برو out;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	اگر ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		برو out;
	}
	اگر (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	اگر ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		برو out;
	}

	اگر (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		برو out;
	}

	انتخاب (socks_atyp) {
	حالت SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		بشکن;
	حالت SSH_SOCKS5_DOMAIN:
		اگر ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			برو out;
		}
		af = -1;
		بشکن;
	حالت SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		بشکن;
	پیشفرض:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		برو out;
	}
	اگر ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		برو out;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	اگر ((r = sshbuf_consume_upto_child(درون_داد, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	آزاد(c->path);
	c->path = پوچ;
	اگر (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->path = xstrdup(dest_addr);
	وگرنه {
		اگر (inet_ntop(af, dest_addr, ntop, اندازه(ntop)) == پوچ)
			بازگشت -1;
		c->path = xstrdup(ntop);
	}
	c->host_port = dest_port;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->path, c->host_port, socks_cmd);

	/* Reply */
	اگر ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/* version */
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
	بازگشت success;
}

Channel *
channel_connect_stdio_fwd(ساختار ssh *ssh,
    ثابت نویسه *host_to_connect, صحیح port_to_connect,
    صحیح in, صحیح out, صحیح nonblock)
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

	بازگشت c;
}

/* dynamic port forwarding */
ایستا تهی
channel_pre_dynamic(ساختار ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	صحیح r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->درون_داد);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	اگر (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		بازگشت;
	}
	/* try to guess the protocol */
	اگر ((r = sshbuf_peek_u8(c->درون_داد, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	انتخاب (ver) {
	حالت 0x04:
		ret = channel_decode_socks4(c, c->درون_داد, c->output);
		بشکن;
	حالت 0x05:
		ret = channel_decode_socks5(c, c->درون_داد, c->output);
		بشکن;
	پیشفرض:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		بشکن;
	}
	اگر (ret < 0) {
		chan_mark_dead(ssh, c);
	} وگرنه اگر (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		اگر (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} وگرنه {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		port_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
ایستا تهی
rdynamic_close(ساختار ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
ایستا تهی
channel_before_prepare_io_rdynamic(ساختار ssh *ssh, Channel *c)
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
		بازگشت;
	}
	/* check if the fixed size part of the packet is in buffer. */
	اگر (have < 3)
		بازگشت;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	انتخاب (p[0]) {
	حالت 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->درون_داد);
		بشکن;
	حالت 0x05:
		ret = channel_decode_socks5(c, c->output, c->درون_داد);
		بشکن;
	پیشفرض:
		ret = -1;
		بشکن;
	}
	اگر (ret < 0) {
		rdynamic_close(ssh, c);
	} وگرنه اگر (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->درون_داد);
		اگر (len > 0 && len < c->remote_window) {
			اگر ((r = sshpkt_start(ssh, SSH2_پیام_CHANNEL_DATA)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->درون_داد)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			اگر ((r = sshbuf_consume(c->درون_داد, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_window -= len;
		}
	} وگرنه اگر (rdynamic_connect_finish(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
ایستا تهی
channel_post_x11_listener(ساختار ssh *ssh, Channel *c)
{
	Channel *nc;
	ساختار sockaddr_storage addr;
	صحیح r, newsock, oerrno, remote_port;
	socklen_t addrlen;
	نویسه buf[16384], *remote_ipaddr;

	اگر ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		بازگشت;

	debug("X11 connection requested.");
	addrlen = اندازه(addr);
	newsock = accept(c->sock, (ساختار sockaddr *)&addr, &addrlen);
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
		بازگشت;
	}
	set_nodelay(newsock);
	اگر (ssh->chanctxt->want_tcp_keepalive)
		set_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_port = get_peer_port(newsock);
	snprintf(buf, اندازه buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_port);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	اگر ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_port)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	اگر ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	آزاد(remote_ipaddr);
}

ایستا تهی
port_open_helper(ساختار ssh *ssh, Channel *c, نویسه *rtype)
{
	نویسه *local_ipaddr = get_local_ipaddr(c->sock);
	صحیح local_port = c->sock == -1 ? 65536 : get_local_port(c->sock);
	نویسه *remote_ipaddr = get_peer_ipaddr(c->sock);
	صحیح remote_port = get_peer_port(c->sock);
	صحیح r;

	اگر (remote_port == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		آزاد(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_port = 65535;
	}

	آزاد(c->remote_name);
	xasprintf(&c->remote_name,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d to %.100s port %d",
	    rtype, c->listening_port, c->path, c->host_port,
	    remote_ipaddr, remote_port, local_ipaddr, local_port);

	open_preamble(ssh, __func__, c, rtype);
	اگر (strcmp(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		اگر ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} وگرنه اگر (strcmp(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		اگر ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} وگرنه اگر (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		اگر ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} وگرنه {
		/* listen address, port */
		اگر ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	اگر (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		اگر ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} وگرنه {
		/* originator host and port */
		اگر ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	اگر ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	آزاد(remote_ipaddr);
	آزاد(local_ipaddr);
}

تهی
channel_set_x11_refuse_time(ساختار ssh *ssh, دوگانه refuse_time)
{
	ssh->chanctxt->x11_refuse_time = refuse_time;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
ایستا تهی
channel_post_port_listener(ساختار ssh *ssh, Channel *c)
{
	Channel *nc;
	ساختار sockaddr_storage addr;
	صحیح newsock, nextstate;
	socklen_t addrlen;
	نویسه *rtype;

	اگر ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		بازگشت;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_port, c->path, c->host_port);

	اگر (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} وگرنه اگر (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} وگرنه اگر (c->host_port == PORT_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} وگرنه اگر (c->host_port == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} وگرنه {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = اندازه(addr);
	newsock = accept(c->sock, (ساختار sockaddr *)&addr, &addrlen);
	اگر (newsock == -1) {
		اگر (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		اگر (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		بازگشت;
	}
	اگر (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		set_nodelay(newsock);
		اگر (ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_port = c->listening_port;
	nc->host_port = c->host_port;
	اگر (c->path != پوچ)
		nc->path = xstrdup(c->path);

	اگر (nextstate != SSH_CHANNEL_DYNAMIC)
		port_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
ایستا تهی
channel_post_auth_listener(ساختار ssh *ssh, Channel *c)
{
	Channel *nc;
	صحیح r, newsock;
	ساختار sockaddr_storage addr;
	socklen_t addrlen;

	اگر ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		بازگشت;

	addrlen = اندازه(addr);
	newsock = accept(c->sock, (ساختار sockaddr *)&addr, &addrlen);
	اگر (newsock == -1) {
		error("accept from auth socket: %.100s", strerror(errno));
		اگر (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		بازگشت;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	اگر ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

ایستا تهی
channel_post_connecting(ساختار ssh *ssh, Channel *c)
{
	صحیح err = 0, sock, isopen, r;
	socklen_t sz = اندازه(err);

	اگر ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		بازگشت;
	اگر (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	اگر (c->connect_ctx == پوچ)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_FINISH);

	اگر (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = errno;
		error("getsockopt SO_ERROR failed");
	}

	اگر (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		اگر (isopen) {
			/* no message necessary */
		} وگرنه {
			اگر ((r = sshpkt_start(ssh,
			    SSH2_پیام_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		بازگشت;
	}
	اگر (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		بازگشت;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, strerror(err));

	/* Try next address, if any */
	اگر ((sock = connect_next(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		اگر (isopen) {
			rdynamic_close(ssh, c);
		} وگرنه {
			اگر ((r = sshpkt_start(ssh,
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

ایستا صحیح
channel_handle_rfd(ساختار ssh *ssh, Channel *c)
{
	نویسه buf[CHAN_RBUF];
	ssize_t len;
	صحیح r, force;
	size_t nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	صحیح pty_zeroread = 0;

#ifdef PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#endif

	force = c->isatty && c->detach_close && c->istate != CHAN_درون_داد_CLOSED;

	اگر (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		بازگشت 1;
	اگر ((avail = sshbuf_avail(c->درون_داد)) == 0)
		بازگشت 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	اگر (!pty_zeroread && c->درون_داد_filter == پوچ && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		اگر (c->type == SSH_CHANNEL_OPEN) {
			اگر ((have = sshbuf_len(c->درون_داد)) >= c->remote_window)
				بازگشت 1; /* shouldn't happen */
			اگر (maxlen > c->remote_window - have)
				maxlen = c->remote_window - have;
		}
		اگر (maxlen > avail)
			maxlen = avail;
		اگر ((r = sshbuf_read(c->rfd, c->درون_داد, maxlen, &nr)) != 0) {
			اگر (errno == EINTR || (!force &&
			    (errno == EAGAIN || errno == EWOULDBLOCK)))
				بازگشت 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			برو rfail;
		}
		اگر (nr != 0)
			channel_set_used_time(ssh, c);
		بازگشت 1;
	}

	errno = 0;
	len = اقرأ(c->rfd, buf, اندازه(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	اگر (pty_zeroread && len == 0 && errno != 0)
		len = -1;
	اگر (len == -1 && (errno == EINTR ||
	    ((errno == EAGAIN || errno == EWOULDBLOCK) && !force)))
		بازگشت 1;
	اگر (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : strerror(errno));
 rfail:
		اگر (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			بازگشت -1;
		} وگرنه {
			chan_read_failed(ssh, c);
		}
		بازگشت -1;
	}
	channel_set_used_time(ssh, c);
	اگر (c->درون_داد_filter != پوچ) {
		اگر (c->درون_داد_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} وگرنه اگر (c->datagram) {
		اگر ((r = sshbuf_put_string(c->درون_داد, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} وگرنه اگر ((r = sshbuf_put(c->درون_داد, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	بازگشت 1;
}

ایستا صحیح
channel_handle_wfd(ساختار ssh *ssh, Channel *c)
{
	ساختار termios tio;
	u_char *data = پوچ, *buf; /* XXX const; need filter API change */
	size_t dlen, olen = 0;
	صحیح r, len;

	اگر ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		بازگشت 1;
	اگر (sshbuf_len(c->output) == 0)
		بازگشت 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	اگر (c->output_filter != پوچ) {
		اگر ((buf = c->output_filter(ssh, c, &data, &dlen)) == پوچ) {
			debug2("channel %d: filter stops", c->self);
			اگر (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			وگرنه
				chan_write_failed(ssh, c);
			بازگشت -1;
		}
	} وگرنه اگر (c->datagram) {
		اگر ((r = sshbuf_get_string(c->output, &data, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = data;
	} وگرنه {
		buf = data = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	اگر (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = اكتب(c->wfd, buf, dlen);
		آزاد(data);
		اگر (len == -1 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK))
			بازگشت 1;
		اگر (len <= 0)
			برو write_fail;
		برو out;
	}

#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	اگر (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#endif

	len = اكتب(c->wfd, buf, dlen);
	اگر (len == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		بازگشت 1;
	اگر (len <= 0) {
 write_fail:
		اگر (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			بازگشت -1;
		} وگرنه {
			chan_write_failed(ssh, c);
		}
		بازگشت -1;
	}
	channel_set_used_time(ssh, c);
#ifndef BROKEN_TCGETATTR_ICANON
	اگر (c->isatty && dlen >= 1 && buf[0] != '\r') {
		اگر (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			اگر ((r = sshpkt_پیام_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#endif /* BROKEN_TCGETATTR_ICANON */
	اگر ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 out:
	c->local_consumed += olen - sshbuf_len(c->output);

	بازگشت 1;
}

ایستا صحیح
channel_handle_efd_write(ساختار ssh *ssh, Channel *c)
{
	صحیح r;
	ssize_t len;

	اگر ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		بازگشت 1;
	اگر (sshbuf_len(c->extended) == 0)
		بازگشت 1;

	len = اكتب(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	اگر (len == -1 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		بازگشت 1;
	اگر (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} وگرنه {
		اگر ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_set_used_time(ssh, c);
	}
	بازگشت 1;
}

ایستا صحیح
channel_handle_efd_read(ساختار ssh *ssh, Channel *c)
{
	نویسه buf[CHAN_RBUF];
	ssize_t len;
	صحیح r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_درون_داد_CLOSED;

	اگر (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		بازگشت 1;

	len = اقرأ(c->efd, buf, اندازه(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	اگر (len == -1 && (errno == EINTR || ((errno == EAGAIN ||
	    errno == EWOULDBLOCK) && !force)))
		بازگشت 1;
	اگر (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		بازگشت 1;
	}
	channel_set_used_time(ssh, c);
	اگر (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	وگرنه اگر ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	بازگشت 1;
}

ایستا صحیح
channel_handle_efd(ساختار ssh *ssh, Channel *c)
{
	اگر (c->efd == -1)
		بازگشت 1;

	/** XXX handle drain efd, too */

	اگر (c->extended_usage == CHAN_EXTENDED_WRITE)
		بازگشت channel_handle_efd_write(ssh, c);
	وگرنه اگر (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		بازگشت channel_handle_efd_read(ssh, c);

	بازگشت 1;
}

ایستا صحیح
channel_check_window(ساختار ssh *ssh, Channel *c)
{
	صحیح r;

	اگر (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD)) &&
	    ((c->local_window_max - c->local_window >
	    c->local_maxpacket*3) ||
	    c->local_window < c->local_window_max/2) &&
	    c->local_consumed > 0) {
		اگر (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		اگر ((r = sshpkt_start(ssh,
		    SSH2_پیام_CHANNEL_WINDOW_ADJUST)) != 0 ||
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
	بازگشت 1;
}

ایستا تهی
channel_post_open(ساختار ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_window(ssh, c);
}

ایستا u_int
read_mux(ساختار ssh *ssh, Channel *c, u_int need)
{
	نویسه buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	صحیح r;

	اگر (sshbuf_len(c->درون_داد) < need) {
		rlen = need - sshbuf_len(c->درون_داد);
		len = اقرأ(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		اگر (len == -1 && (errno == EINTR || errno == EAGAIN))
			بازگشت sshbuf_len(c->درون_داد);
		اگر (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			بازگشت 0;
		} وگرنه اگر ((r = sshbuf_put(c->درون_داد, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	بازگشت sshbuf_len(c->درون_داد);
}

ایستا تهی
channel_post_mux_client_read(ساختار ssh *ssh, Channel *c)
{
	u_int need;

	اگر ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		بازگشت;
	اگر (c->istate != CHAN_درون_داد_OPEN && c->istate != CHAN_درون_داد_WAIT_DRAIN)
		بازگشت;
	اگر (c->mux_pause)
		بازگشت;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	اگر (read_mux(ssh, c, 4) < 4) /* read header */
		بازگشت;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->درون_داد));
#define CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	اگر (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		بازگشت;
	}
	اگر (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		بازگشت;
	اگر (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		بازگشت;
	}
}

ایستا تهی
channel_post_mux_client_write(ساختار ssh *ssh, Channel *c)
{
	ssize_t len;
	صحیح r;

	اگر ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		بازگشت;
	اگر (sshbuf_len(c->output) == 0)
		بازگشت;

	len = اكتب(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	اگر (len == -1 && (errno == EINTR || errno == EAGAIN))
		بازگشت;
	اگر (len <= 0) {
		chan_mark_dead(ssh, c);
		بازگشت;
	}
	اگر ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

ایستا تهی
channel_post_mux_client(ساختار ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

ایستا تهی
channel_post_mux_listener(ساختار ssh *ssh, Channel *c)
{
	Channel *nc;
	ساختار sockaddr_storage addr;
	socklen_t addrlen;
	صحیح newsock;
	uid_t euid;
	gid_t egid;

	اگر ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		بازگشت;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, اندازه(addr));
	addrlen = اندازه(addr);
	اگر ((newsock = accept(c->sock, (ساختار sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", strerror(errno));
		اگر (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		بازگشت;
	}

	اگر (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", strerror(errno));
		close(newsock);
		بازگشت;
	}
	اگر ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		بازگشت;
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

ایستا تهی
channel_handler_init(ساختار ssh_channels *sc)
{
	chan_fn **pre, **post;

	اگر ((pre = calloc(SSH_CHANNEL_MAX_TYPE, اندازه(*pre))) == پوچ ||
	    (post = calloc(SSH_CHANNEL_MAX_TYPE, اندازه(*post))) == پوچ)
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
ایستا تهی
channel_garbage_collect(ساختار ssh *ssh, Channel *c)
{
	اگر (c == پوچ)
		بازگشت;
	اگر (c->detach_user != پوچ) {
		اگر (!chan_is_dead(ssh, c, c->detach_close))
			بازگشت;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, پوچ);
		/* if we still have a callback */
		اگر (c->detach_user != پوچ)
			بازگشت;
		debug2("channel %d: gc: user detached", c->self);
	}
	اگر (!chan_is_dead(ssh, c, 1))
		بازگشت;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

شمارش channel_table { CHAN_PRE, CHAN_POST };

ایستا تهی
channel_handler(ساختار ssh *ssh, صحیح table, ساختار timespec *timeout)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = table == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	دوگانه now;

	now = monotime_double();
	برای (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		اگر (c == پوچ)
			ادامه;
		/* Count open channels in bulk state */
		اگر (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		اگر (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			ادامه;
		اگر (c->delayed) {
			اگر (table == CHAN_PRE)
				c->delayed = 0;
			وگرنه
				ادامه;
		}
		اگر (ftab[c->type] != پوچ) {
			اگر (table == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				دوگانه deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} وگرنه اگر (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				اگر (timeout != پوچ &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} وگرنه اگر (timeout != پوچ) {
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
ایستا تهی
channel_before_prepare_io(ساختار ssh *ssh)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	برای (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		اگر (c == پوچ)
			ادامه;
		اگر (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

ایستا تهی
dump_channel_poll(ثابت نویسه *func, ثابت نویسه *what, Channel *c,
    u_int pollfd_offset, ساختار pollfd *pfd)
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
ایستا تهی
channel_prepare_pollfd(Channel *c, u_int *next_pollfd,
    ساختار pollfd *pfd, u_int npfd)
{
	u_int ev, p = *next_pollfd;

	اگر (c == پوچ)
		بازگشت;
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
	*next_pollfd = p;
}

/* * Allocate/prepare poll structure */
تهی
channel_prepare_poll(ساختار ssh *ssh, ساختار pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, ساختار timespec *timeout)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	برای (i = 0; i < sc->channels_alloc; i++) {
		اگر (sc->channels[i] == پوچ)
			ادامه;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	اگر (sc->channels_alloc >= (INT_MAX / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	اگر (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, اندازه(**pfdp));
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
	برای (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

ایستا تهی
fd_ready(Channel *c, صحیح p, ساختار pollfd *pfds, u_int npfd, صحیح fd,
    ثابت نویسه *what, u_int revents_mask, u_int ready)
{
	ساختار pollfd *pfd = &pfds[p];

	اگر (fd == -1)
		بازگشت;
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
	اگر ((pfd->revents & (revents_mask|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
تهی
channel_after_poll(ساختار ssh *ssh, ساختار pollfd *pfd, u_int npfd)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	u_int i;
	صحیح p;
	Channel *c;

#ifdef DEBUG_CHANNEL_POLL
	برای (p = 0; p < (صحیح)npfd; p++) {
		اگر (pfd[p].revents == 0)
			ادامه;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#endif

	/* Convert pollfd into c->io_ready */
	برای (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		اگر (c == پوچ)
			ادامه;
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
	channel_handler(ssh, CHAN_POST, پوچ);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
ایستا صحیح
channel_output_poll_درون_داد_open(ساختار ssh *ssh, Channel *c)
{
	size_t len, plen;
	ثابت u_char *pkt;
	صحیح r;

	اگر ((len = sshbuf_len(c->درون_داد)) == 0) {
		اگر (c->istate == CHAN_درون_داد_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			اگر (CHANNEL_EFD_درون_داد_ACTIVE(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			وگرنه
				chan_ibuf_empty(ssh, c);
		}
		بازگشت 0;
	}

	اگر (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	اگر (c->datagram) {
		/* Check datagram will fit; drop if not */
		اگر ((r = sshbuf_get_string_direct(c->درون_داد, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		اگر (plen > c->remote_window || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			بازگشت 0;
		}
		/* Enqueue it */
		اگر ((r = sshpkt_start(ssh, SSH2_پیام_CHANNEL_DATA)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_window -= plen;
		بازگشت 1;
	}

	/* Enqueue packet for buffered data. */
	اگر (len > c->remote_window)
		len = c->remote_window;
	اگر (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	اگر (len == 0)
		بازگشت 0;
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_CHANNEL_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->درون_داد), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	اگر ((r = sshbuf_consume(c->درون_داد, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	بازگشت 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
ایستا صحیح
channel_output_poll_extended_read(ساختار ssh *ssh, Channel *c)
{
	size_t len;
	صحیح r;

	اگر ((len = sshbuf_len(c->extended)) == 0)
		بازگشت 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_window, sshbuf_len(c->extended), c->extended_usage);
	اگر (len > c->remote_window)
		len = c->remote_window;
	اگر (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	اگر (len == 0)
		بازگشت 0;
	اگر (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_CHANNEL_EXTENDED_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_DATA_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	اگر ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	بازگشت 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
صحیح
channel_output_poll(ساختار ssh *ssh)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	صحیح ret = 0;

	برای (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		اگر (c == پوچ)
			ادامه;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		اگر (c->type != SSH_CHANNEL_OPEN)
			ادامه;
		اگر ((c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			ادامه;
		}

		/* Get the amount of buffered data for this channel. */
		اگر (c->istate == CHAN_درون_داد_OPEN ||
		    c->istate == CHAN_درون_داد_WAIT_DRAIN)
			ret |= channel_output_poll_درون_داد_open(ssh, c);
		/* Send extended data, i.e. stderr */
		اگر (!(c->flags & CHAN_EOF_SENT) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	بازگشت ret;
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
channel_proxy_downstream(ساختار ssh *ssh, Channel *downstream)
{
	Channel *c = پوچ;
	ساختار sshbuf *original = پوچ, *modified = پوچ;
	ثابت u_char *cp;
	نویسه *ctype = پوچ, *listen_host = پوچ;
	u_char type;
	size_t have;
	صحیح ret = -1, r;
	u_int id, remote_id, listen_port;

	/* sshbuf_dump(downstream->input, stderr); */
	اگر ((r = sshbuf_get_string_direct(downstream->درون_داد, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		بازگشت -1;
	}
	اگر (have < 2) {
		error_f("short message");
		بازگشت -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	اگر (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	انتخاب (type) {
	حالت SSH2_پیام_CHANNEL_OPEN:
		اگر ((original = sshbuf_from(cp, have)) == پوچ ||
		    (modified = sshbuf_new()) == پوچ) {
			error_f("alloc");
			برو out;
		}
		اگر ((r = sshbuf_get_cstring(original, &ctype, پوچ)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			برو out;
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
			برو out;
		}
		بشکن;
	حالت SSH2_پیام_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		اگر ((original = sshbuf_from(cp, have)) == پوچ ||
		    (modified = sshbuf_new()) == پوچ) {
			error_f("alloc");
			برو out;
		}
		اگر ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			برو out;
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
			برو out;
		}
		بشکن;
	حالت SSH2_پیام_GLOBAL_REQUEST:
		اگر ((original = sshbuf_from(cp, have)) == پوچ) {
			error_f("alloc");
			برو out;
		}
		اگر ((r = sshbuf_get_cstring(original, &ctype, پوچ)) != 0) {
			error_fr(r, "parse");
			برو out;
		}
		اگر (strcmp(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			برو out;
		}
		اگر ((r = sshbuf_get_u8(original, پوچ)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, پوچ)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_port)) != 0) {
			error_fr(r, "parse");
			برو out;
		}
		اگر (listen_port > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_port);
			برو out;
		}
		/* Record that connection to this host/port is permitted. */
		permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, پوچ, (صحیح)listen_port, downstream);
		بشکن;
	حالت SSH2_پیام_CHANNEL_CLOSE:
		اگر (have < 4)
			بشکن;
		remote_id = PEEK_U32(cp);
		اگر ((c = channel_by_remote_id(ssh, remote_id)) != پوچ) {
			اگر (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			وگرنه
				c->flags |= CHAN_CLOSE_SENT;
		}
		بشکن;
	}
	اگر (modified) {
		اگر ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			برو out;
		}
	} وگرنه {
		اگر ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			برو out;
		}
	}
	ret = 0;
 out:
	آزاد(ctype);
	آزاد(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	بازگشت ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
صحیح
channel_proxy_upstream(Channel *c, صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	ساختار sshbuf *b = پوچ;
	Channel *downstream;
	ثابت u_char *cp = پوچ;
	size_t len;
	صحیح r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	اگر (c == پوچ || c->type != SSH_CHANNEL_MUX_PROXY)
		بازگشت 0;
	اگر ((downstream = c->mux_ctx) == پوچ)
		بازگشت 0;
	انتخاب (type) {
	حالت SSH2_پیام_CHANNEL_CLOSE:
	حالت SSH2_پیام_CHANNEL_DATA:
	حالت SSH2_پیام_CHANNEL_EOF:
	حالت SSH2_پیام_CHANNEL_EXTENDED_DATA:
	حالت SSH2_پیام_CHANNEL_OPEN_CONFIRMATION:
	حالت SSH2_پیام_CHANNEL_OPEN_FAILURE:
	حالت SSH2_پیام_CHANNEL_WINDOW_ADJUST:
	حالت SSH2_پیام_CHANNEL_SUCCESS:
	حالت SSH2_پیام_CHANNEL_FAILURE:
	حالت SSH2_پیام_CHANNEL_REQUEST:
		بشکن;
	پیشفرض:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		بازگشت 0;
	}
	اگر ((b = sshbuf_new()) == پوچ) {
		error_f("alloc reply");
		برو out;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	اگر (cp == پوچ) {
		error_f("no packet");
		برو out;
	}
	/* translate id and send to muxclient */
	اگر ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		برو out;
	}
	/* sshbuf_dump(b, stderr); */
	اگر (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 out:
	/* update state */
	انتخاب (type) {
	حالت SSH2_پیام_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		اگر (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		بشکن;
	حالت SSH2_پیام_CHANNEL_CLOSE:
		اگر (c->flags & CHAN_CLOSE_SENT)
			channel_free(ssh, c);
		وگرنه
			c->flags |= CHAN_CLOSE_RCVD;
		بشکن;
	}
	sshbuf_free(b);
	بازگشت 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
ایستا صحیح
channel_parse_id(ساختار ssh *ssh, ثابت نویسه *where, ثابت نویسه *what)
{
	uint32_t id;
	صحیح r;

	اگر ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	اگر (id > INT_MAX) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	بازگشت (صحیح)id;
}

/* Lookup a channel from an ID in the current packet */
ایستا Channel *
channel_from_packet_id(ساختار ssh *ssh, ثابت نویسه *where, ثابت نویسه *what)
{
	صحیح id = channel_parse_id(ssh, where, what);
	Channel *c;

	اگر ((c = channel_lookup(ssh, id)) == پوچ) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	بازگشت c;
}

صحیح
channel_درون_داد_data(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	ثابت u_char *data;
	size_t data_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	صحیح r;

	اگر (channel_proxy_upstream(c, type, seq, ssh))
		بازگشت 0;

	/* Ignore any data for non-open channels (might happen on close) */
	اگر (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_FINISH &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		بازگشت 0;

	/* Get the data. */
	اگر ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = data_len;
	اگر (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	اگر (c->ostate != CHAN_OUTPUT_OPEN) {
		اگر (win_len > c->local_window)
			c->local_window = 0;
		وگرنه
			c->local_window -= win_len;
		c->local_consumed += win_len;
		بازگشت 0;
	}

	اگر (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		بازگشت 0;
	}
	اگر (win_len > c->local_window) {
		u_int delta = win_len - c->local_window;

		اگر (c->local_window_exceeded > UINT_MAX - delta)
			c->local_window_exceeded = UINT_MAX;
		وگرنه
			c->local_window_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_window,
		    c->local_window_max, c->local_window_exceeded);
		c->local_window = 0;
		/* Allow 10% grace before bringing the hammer down */
		اگر (c->local_window_exceeded > (c->local_window_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} وگرنه {
		c->local_window -= win_len;
		c->local_window_exceeded = 0;
	}

	اگر (c->datagram) {
		اگر ((r = sshbuf_put_string(c->output, data, data_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} وگرنه اگر ((r = sshbuf_put(c->output, data, data_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	بازگشت 0;
}

صحیح
channel_درون_داد_extended_data(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	ثابت u_char *data;
	size_t data_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	صحیح r;

	اگر (channel_proxy_upstream(c, type, seq, ssh))
		بازگشت 0;
	اگر (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		بازگشت 0;
	}
	اگر (c->flags & CHAN_EOF_RCVD) {
		اگر (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		وگرنه
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	اگر ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	اگر (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_DATA_STDERR) {
		logit("channel %d: bad ext data", c->self);
		بازگشت 0;
	}
	اگر ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	اگر (data_len > c->local_window) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, data_len, c->local_window);
		بازگشت 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, data_len);
	/* XXX sshpkt_getb? */
	اگر ((r = sshbuf_put(c->extended, data, data_len)) != 0)
		error_fr(r, "append");
	c->local_window -= data_len;
	بازگشت 0;
}

صحیح
channel_درون_داد_ieof(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	صحیح r;

        اگر ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	اگر (channel_proxy_upstream(c, type, seq, ssh))
		بازگشت 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	اگر (c->force_drain && c->istate == CHAN_درون_داد_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_درون_داد_WAIT_DRAIN;
		اگر (sshbuf_len(c->درون_داد) == 0)
			chan_ibuf_empty(ssh, c);
	}
	بازگشت 0;
}

صحیح
channel_درون_داد_oclose(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	صحیح r;

	اگر (channel_proxy_upstream(c, type, seq, ssh))
		بازگشت 0;
        اگر ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	بازگشت 0;
}

صحیح
channel_درون_داد_open_confirmation(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_window, remote_maxpacket;
	صحیح r;

	اگر (channel_proxy_upstream(c, type, seq, ssh))
		بازگشت 0;
	اگر (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	اگر ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
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
	اگر (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_set_used_time(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_window, c->remote_maxpacket);
	بازگشت 0;
}

ایستا نویسه *
reason2txt(صحیح reason)
{
	انتخاب (reason) {
	حالت SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		بازگشت "administratively prohibited";
	حالت SSH2_OPEN_CONNECT_FAILED:
		بازگشت "connect failed";
	حالت SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		بازگشت "unknown channel type";
	حالت SSH2_OPEN_RESOURCE_SHORTAGE:
		بازگشت "resource shortage";
	}
	بازگشت "unknown reason";
}

صحیح
channel_درون_داد_open_failure(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	نویسه *پیام = پوچ;
	صحیح r;

	اگر (channel_proxy_upstream(c, type, seq, ssh))
		بازگشت 0;
	اگر (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	اگر ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	اگر ((r = sshpkt_get_cstring(ssh, &پیام, پوچ)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, پوچ, پوچ)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), پیام ? ": ": "", پیام ? پیام : "");
	آزاد(پیام);
	اگر (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	بازگشت 0;
}

صحیح
channel_درون_داد_window_adjust(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	صحیح id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	صحیح r;

	اگر ((c = channel_lookup(ssh, id)) == پوچ) {
		logit("Received window adjust for non-open channel %d.", id);
		بازگشت 0;
	}

	اگر (channel_proxy_upstream(c, type, seq, ssh))
		بازگشت 0;
	اگر ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	اگر ((new_rwin = c->remote_window + adjust) < c->remote_window) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_window);
	}
	c->remote_window = new_rwin;
	بازگشت 0;
}

صحیح
channel_درون_داد_status_confirm(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	صحیح id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	ساختار channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_set_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	اگر ((c = channel_lookup(ssh, id)) == پوچ) {
		logit_f("%d: unknown", id);
		بازگشت 0;
	}
	اگر (channel_proxy_upstream(c, type, seq, ssh))
		بازگشت 0;
        اگر (sshpkt_get_end(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	اگر ((cc = TAILQ_FIRST(&c->status_confirms)) == پوچ)
		بازگشت 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->status_confirms, cc, entry);
	freezero(cc, اندازه(*cc));
	بازگشت 0;
}

/* -- tcp forwarding */

تهی
channel_set_af(ساختار ssh *ssh, صحیح af)
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
ایستا ثابت نویسه *
channel_fwd_bind_addr(ساختار ssh *ssh, ثابت نویسه *listen_addr, صحیح *wildcardp,
    صحیح is_client, ساختار ForwardOptions *fwd_opts)
{
	ثابت نویسه *addr = پوچ;
	صحیح wildcard = 0;

	اگر (listen_addr == پوچ) {
		/* No address specified: default to gateway_ports setting */
		اگر (fwd_opts->gateway_ports)
			wildcard = 1;
	} وگرنه اگر (fwd_opts->gateway_ports || is_client) {
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
		} وگرنه اگر (strcmp(listen_addr, "localhost") != 0 ||
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
	} وگرنه اگر (strcmp(listen_addr, "127.0.0.1") == 0 ||
	    strcmp(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	اگر (wildcardp != پوچ)
		*wildcardp = wildcard;
	بازگشت addr;
}

ایستا صحیح
channel_setup_fwd_listener_tcpip(ساختار ssh *ssh, صحیح type,
    ساختار Forward *fwd, صحیح *allocated_listen_port,
    ساختار ForwardOptions *fwd_opts)
{
	Channel *c;
	صحیح sock, r, success = 0, wildcard = 0, is_client;
	ساختار addrinfo hints, *ai, *aitop;
	ثابت نویسه *host, *addr;
	نویسه ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_PORT_LISTENER);

	اگر (is_client && fwd->connect_path != پوچ) {
		host = fwd->connect_path;
	} وگرنه {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		اگر (host == پوچ) {
			error("No forward host name.");
			بازگشت 0;
		}
		اگر (strlen(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			بازگشت 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == پوچ) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, اندازه(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, اندازه strport, "%d", fwd->listen_port);
	اگر ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		اگر (addr == پوچ) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} وگرنه {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		بازگشت 0;
	}
	اگر (allocated_listen_port != پوچ)
		*allocated_listen_port = 0;
	برای (ai = aitop; ai; ai = ai->ai_next) {
		انتخاب (ai->ai_family) {
		حالت AF_INET:
			lport_p = &((ساختار sockaddr_in *)ai->ai_addr)->
			    sin_port;
			بشکن;
		حالت AF_INET6:
			lport_p = &((ساختار sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			بشکن;
		پیشفرض:
			ادامه;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		اگر (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 && allocated_listen_port != پوچ &&
		    *allocated_listen_port > 0)
			*lport_p = htons(*allocated_listen_port);

		اگر (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, اندازه(ntop),
		    strport, اندازه(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			ادامه;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		اگر (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			ادامه;
		}

		set_reuseaddr(sock);
		اگر (ai->ai_family == AF_INET6)
			sock_set_v6only(sock);

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
			وگرنه
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));

			close(sock);
			ادامه;
		}
		/* Start listening for connections on the socket. */
		اگر (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			close(sock);
			ادامه;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		اگر (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 &&
		    allocated_listen_port != پوچ &&
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
		c->listening_addr = addr == پوچ ? پوچ : xstrdup(addr);
		اگر (fwd->listen_port == 0 && allocated_listen_port != پوچ &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_port = *allocated_listen_port;
		وگرنه
			c->listening_port = fwd->listen_port;
		success = 1;
	}
	اگر (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_port);
	freeaddrinfo(aitop);
	بازگشت success;
}

ایستا صحیح
channel_setup_fwd_listener_streamlocal(ساختار ssh *ssh, صحیح type,
    ساختار Forward *fwd, ساختار ForwardOptions *fwd_opts)
{
	ساختار sockaddr_un sunaddr;
	ثابت نویسه *path;
	Channel *c;
	صحیح port, sock;
	mode_t omask;

	انتخاب (type) {
	حالت SSH_CHANNEL_UNIX_LISTENER:
		اگر (fwd->connect_path != پوچ) {
			اگر (strlen(fwd->connect_path) > اندازه(sunaddr.sun_path)) {
				error("Local connecting path too long: %s",
				    fwd->connect_path);
				بازگشت 0;
			}
			path = fwd->connect_path;
			port = PORT_STREAMLOCAL;
		} وگرنه {
			اگر (fwd->connect_host == پوچ) {
				error("No forward host name.");
				بازگشت 0;
			}
			اگر (strlen(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				بازگشت 0;
			}
			path = fwd->connect_host;
			port = fwd->connect_port;
		}
		بشکن;
	حالت SSH_CHANNEL_RUNIX_LISTENER:
		path = fwd->listen_path;
		port = PORT_STREAMLOCAL;
		بشکن;
	پیشفرض:
		error_f("unexpected channel type %d", type);
		بازگشت 0;
	}

	اگر (fwd->listen_path == پوچ) {
		error("No forward path name.");
		بازگشت 0;
	}
	اگر (strlen(fwd->listen_path) > اندازه(sunaddr.sun_path)) {
		error("Local listening path too long: %s", fwd->listen_path);
		بازگشت 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_path);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_mask);
	sock = unix_listener(fwd->listen_path, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	اگر (sock < 0)
		بازگشت 0;

	debug("Local forwarding listening on path %s.", fwd->listen_path);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->path = xstrdup(path);
	c->host_port = port;
	c->listening_port = PORT_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_path);
	بازگشت 1;
}

ایستا صحیح
channel_cancel_rport_listener_tcpip(ساختار ssh *ssh,
    ثابت نویسه *host, u_short port)
{
	u_int i;
	صحیح found = 0;

	برای (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		اگر (c == پوچ || c->type != SSH_CHANNEL_RPORT_LISTENER)
			ادامه;
		اگر (strcmp(c->path, host) == 0 && c->listening_port == port) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	بازگشت found;
}

ایستا صحیح
channel_cancel_rport_listener_streamlocal(ساختار ssh *ssh, ثابت نویسه *path)
{
	u_int i;
	صحیح found = 0;

	برای (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		اگر (c == پوچ || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			ادامه;
		اگر (c->path == پوچ)
			ادامه;
		اگر (strcmp(c->path, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	بازگشت found;
}

صحیح
channel_cancel_rport_listener(ساختار ssh *ssh, ساختار Forward *fwd)
{
	اگر (fwd->listen_path != پوچ) {
		بازگشت channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} وگرنه {
		بازگشت channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port);
	}
}

ایستا صحیح
channel_cancel_lport_listener_tcpip(ساختار ssh *ssh,
    ثابت نویسه *lhost, u_short lport, صحیح cport,
    ساختار ForwardOptions *fwd_opts)
{
	u_int i;
	صحیح found = 0;
	ثابت نویسه *addr = channel_fwd_bind_addr(ssh, lhost, پوچ, 1, fwd_opts);

	برای (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		اگر (c == پوچ || c->type != SSH_CHANNEL_PORT_LISTENER)
			ادامه;
		اگر (c->listening_port != lport)
			ادامه;
		اگر (cport == CHANNEL_CANCEL_PORT_STATIC) {
			/* skip dynamic forwardings */
			اگر (c->host_port == 0)
				ادامه;
		} وگرنه {
			اگر (c->host_port != cport)
				ادامه;
		}
		اگر ((c->listening_addr == پوچ && addr != پوچ) ||
		    (c->listening_addr != پوچ && addr == پوچ))
			ادامه;
		اگر (addr == پوچ || strcmp(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	بازگشت found;
}

ایستا صحیح
channel_cancel_lport_listener_streamlocal(ساختار ssh *ssh, ثابت نویسه *path)
{
	u_int i;
	صحیح found = 0;

	اگر (path == پوچ) {
		error_f("no path specified.");
		بازگشت 0;
	}

	برای (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		اگر (c == پوچ || c->type != SSH_CHANNEL_UNIX_LISTENER)
			ادامه;
		اگر (c->listening_addr == پوچ)
			ادامه;
		اگر (strcmp(c->listening_addr, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	بازگشت found;
}

صحیح
channel_cancel_lport_listener(ساختار ssh *ssh,
    ساختار Forward *fwd, صحیح cport, ساختار ForwardOptions *fwd_opts)
{
	اگر (fwd->listen_path != پوچ) {
		بازگشت channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} وگرنه {
		بازگشت channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
صحیح
channel_setup_local_fwd_listener(ساختار ssh *ssh,
    ساختار Forward *fwd, ساختار ForwardOptions *fwd_opts)
{
	اگر (fwd->listen_path != پوچ) {
		بازگشت channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} وگرنه {
		بازگشت channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_PORT_LISTENER, fwd, پوچ, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
ایستا صحیح
remote_open_match(ساختار permission *allowed_open, ساختار Forward *fwd)
{
	صحیح ret;
	نویسه *lhost;

	/* XXX add ACLs for streamlocal */
	اگر (fwd->listen_path != پوچ)
		بازگشت 1;

	اگر (fwd->listen_host == پوچ || allowed_open->listen_host == پوچ)
		بازگشت 0;

	اگر (allowed_open->listen_port != FWD_PERMIT_ANY_PORT &&
	    allowed_open->listen_port != fwd->listen_port)
		بازگشت 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = match_pattern(lhost, allowed_open->listen_host);
	آزاد(lhost);

	بازگشت ret;
}

/* Checks whether a requested remote forwarding is permitted */
ایستا صحیح
check_rfwd_permission(ساختار ssh *ssh, ساختار Forward *fwd)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	ساختار permission_set *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	ساختار permission *perm;

#ifdef SKIP_PRIVDROP
	اگر (fwd->listen_path != پوچ)
		بازگشت 0;
	اگر (fwd->listen_port != 0 && fwd->listen_port < 1024)
		بازگشت 0;
#endif

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	اگر (!permit) {
		برای (i = 0; i < pset->رقم_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			اگر (remote_open_match(perm, fwd)) {
				permit = 1;
				بشکن;
			}
		}
	}

	اگر (pset->رقم_permitted_admin > 0) {
		permit_adm = 0;
		برای (i = 0; i < pset->رقم_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			اگر (remote_open_match(perm, fwd)) {
				permit_adm = 1;
				بشکن;
			}
		}
	}

	بازگشت permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
صحیح
channel_setup_remote_fwd_listener(ساختار ssh *ssh, ساختار Forward *fwd,
    صحیح *allocated_listen_port, ساختار ForwardOptions *fwd_opts)
{
	اگر (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		اگر (fwd->listen_path != پوچ)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_path);
		وگرنه اگر(fwd->listen_host != پوچ)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_host, fwd->listen_port );
		وگرنه
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		بازگشت 0;
	}
	اگر (fwd->listen_path != پوچ) {
		بازگشت channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} وگرنه {
		بازگشت channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_port,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
ایستا ثابت نویسه *
channel_rfwd_bind_host(ثابت نویسه *listen_host)
{
	اگر (listen_host == پوچ) {
		بازگشت "localhost";
	} وگرنه اگر (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		بازگشت "";
	} وگرنه
		بازگشت listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
صحیح
channel_request_remote_forwarding(ساختار ssh *ssh, ساختار Forward *fwd)
{
	صحیح r, success = 0, idx = -1;
	ثابت نویسه *host_to_connect, *listen_host, *listen_path;
	صحیح port_to_connect, listen_port;

	/* Send the forward request to the remote side. */
	اگر (fwd->listen_path != پوچ) {
		اگر ((r = sshpkt_start(ssh, SSH2_پیام_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_path)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} وگرنه {
		اگر ((r = sshpkt_start(ssh, SSH2_پیام_GLOBAL_REQUEST)) != 0 ||
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
	اگر (success) {
		/* Record that connection to this host/port is permitted. */
		host_to_connect = listen_host = listen_path = پوچ;
		port_to_connect = listen_port = 0;
		اگر (fwd->connect_path != پوچ) {
			host_to_connect = fwd->connect_path;
			port_to_connect = PORT_STREAMLOCAL;
		} وگرنه {
			host_to_connect = fwd->connect_host;
			port_to_connect = fwd->connect_port;
		}
		اگر (fwd->listen_path != پوچ) {
			listen_path = fwd->listen_path;
			listen_port = PORT_STREAMLOCAL;
		} وگرنه {
			listen_host = fwd->listen_host;
			listen_port = fwd->listen_port;
		}
		idx = permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_to_connect, port_to_connect,
		    listen_host, listen_path, listen_port, پوچ);
	}
	بازگشت idx;
}

ایستا صحیح
open_match(ساختار permission *allowed_open, ثابت نویسه *requestedhost,
    صحیح requestedport)
{
	اگر (allowed_open->host_to_connect == پوچ)
		بازگشت 0;
	اگر (allowed_open->port_to_connect != FWD_PERMIT_ANY_PORT &&
	    allowed_open->port_to_connect != requestedport)
		بازگشت 0;
	اگر (strcmp(allowed_open->host_to_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    strcmp(allowed_open->host_to_connect, requestedhost) != 0)
		بازگشت 0;
	بازگشت 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
ایستا صحیح
open_listen_match_tcpip(ساختار permission *allowed_open,
    ثابت نویسه *requestedhost, u_short requestedport, صحیح translate)
{
	ثابت نویسه *allowed_host;

	اگر (allowed_open->host_to_connect == پوچ)
		بازگشت 0;
	اگر (allowed_open->listen_port != requestedport)
		بازگشت 0;
	اگر (!translate && allowed_open->listen_host == پوچ &&
	    requestedhost == پوچ)
		بازگشت 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	اگر (allowed_host == پوچ || requestedhost == پوچ ||
	    strcmp(allowed_host, requestedhost) != 0)
		بازگشت 0;
	بازگشت 1;
}

ایستا صحیح
open_listen_match_streamlocal(ساختار permission *allowed_open,
    ثابت نویسه *requestedpath)
{
	اگر (allowed_open->host_to_connect == پوچ)
		بازگشت 0;
	اگر (allowed_open->listen_port != PORT_STREAMLOCAL)
		بازگشت 0;
	اگر (allowed_open->listen_path == پوچ ||
	    strcmp(allowed_open->listen_path, requestedpath) != 0)
		بازگشت 0;
	بازگشت 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
ایستا صحیح
channel_request_rforward_cancel_tcpip(ساختار ssh *ssh,
    ثابت نویسه *host, u_short port)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	ساختار permission_set *pset = &sc->local_perms;
	صحیح r;
	u_int i;
	ساختار permission *perm = پوچ;

	برای (i = 0; i < pset->رقم_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		اگر (open_listen_match_tcpip(perm, host, port, 0))
			بشکن;
		perm = پوچ;
	}
	اگر (perm == پوچ) {
		debug_f("requested forward not found");
		بازگشت -1;
	}
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, port)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	بازگشت 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
ایستا صحیح
channel_request_rforward_cancel_streamlocal(ساختار ssh *ssh, ثابت نویسه *path)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	ساختار permission_set *pset = &sc->local_perms;
	صحیح r;
	u_int i;
	ساختار permission *perm = پوچ;

	برای (i = 0; i < pset->رقم_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		اگر (open_listen_match_streamlocal(perm, path))
			بشکن;
		perm = پوچ;
	}
	اگر (perm == پوچ) {
		debug_f("requested forward not found");
		بازگشت -1;
	}
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, path)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	بازگشت 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
صحیح
channel_request_rforward_cancel(ساختار ssh *ssh, ساختار Forward *fwd)
{
	اگر (fwd->listen_path != پوچ) {
		بازگشت channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_path);
	} وگرنه {
		بازگشت channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_port ? fwd->listen_port : fwd->allocated_port);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
تهی
channel_permit_all(ساختار ssh *ssh, صحیح where)
{
	ساختار permission_set *pset = permission_set_get(ssh, where);

	اگر (pset->رقم_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
تهی
channel_add_permission(ساختار ssh *ssh, صحیح who, صحیح where,
    نویسه *host, صحیح port)
{
	صحیح local = where == FORWARD_LOCAL;
	ساختار permission_set *pset = permission_set_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, port);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_set_add(ssh, who, where,
	    local ? host : پوچ, local ? port : 0,
	    local ? پوچ : host, پوچ, local ? 0 : port, پوچ);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
تهی
channel_disable_admin(ساختار ssh *ssh, صحیح where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_set_add(ssh, FORWARD_ADM, where,
	    پوچ, 0, پوچ, پوچ, 0, پوچ);
}

/*
 * Clear a list of permitted opens.
 */
تهی
channel_clear_permission(ساختار ssh *ssh, صحیح who, صحیح where)
{
	ساختار permission **permp;
	u_int i, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);
	برای (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	آزاد(*permp);
	*permp = پوچ;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
تهی
channel_update_permission(ساختار ssh *ssh, صحیح idx, صحیح newport)
{
	ساختار permission_set *pset = &ssh->chanctxt->local_perms;

	اگر (idx < 0 || (u_int)idx >= pset->رقم_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->رقم_permitted_user);
		بازگشت;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_to_connect,
	    pset->permitted_user[idx].port_to_connect);
	اگر (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	وگرنه {
		pset->permitted_user[idx].listen_port =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
ایستا صحیح
connect_next(ساختار ssh *ssh, ساختار channel_connect *cctx)
{
	صحیح sock, sock_is_network, saved_errno;
	ساختار sockaddr_un *sunaddr;
	نویسه ntop[NI_MAXHOST];
	نویسه strport[MAXIMUM(NI_MAXSERV, اندازه(sunaddr->sun_path))];

	برای (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_network = 0;
		انتخاب (cctx->ai->ai_family) {
		حالت AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (ساختار sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", اندازه(ntop));
			strlcpy(strport, sunaddr->sun_path, اندازه(strport));
			بشکن;
		حالت AF_INET:
		حالت AF_INET6:
			اگر (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, اندازه(ntop), strport, اندازه(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				ادامه;
			}
			sock_is_network = 1;
			بشکن;
		پیشفرض:
			ادامه;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		اگر ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			اگر (cctx->ai->ai_next == پوچ)
				error("socket: %.100s", strerror(errno));
			وگرنه
				verbose("socket: %.100s", strerror(errno));
			ادامه;
		}
		اگر (set_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		اگر (sock_is_network && ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(sock); /* logs errors */
		اگر (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			ادامه;	/* fail -- try next */
		}
		اگر (cctx->ai->ai_family != AF_UNIX)
			set_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		بازگشت sock;
	}
	بازگشت -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
ایستا صحیح
connect_to_helper(ساختار ssh *ssh, ثابت نویسه *name, صحیح port, صحیح socktype,
    نویسه *ctype, نویسه *rname, ساختار channel_connect *cctx,
    صحیح *reason, ثابت نویسه **errmsg)
{
	ساختار addrinfo hints;
	صحیح gaierr;
	صحیح sock = -1;
	نویسه strport[NI_MAXSERV];

	اگر (port == PORT_STREAMLOCAL) {
		ساختار sockaddr_un *sunaddr;
		ساختار addrinfo *ai;

		اگر (strlen(name) > اندازه(sunaddr->sun_path)) {
			error("%.100s: %.100s", name, strerror(ENAMETOOLONG));
			بازگشت -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, اندازه(*ai) + اندازه(*sunaddr));
		ai->ai_addr = (ساختار sockaddr *)(ai + 1);
		ai->ai_addrlen = اندازه(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (ساختار sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_path, name, اندازه(sunaddr->sun_path));
		cctx->aitop = ai;
	} وگرنه {
		memset(&hints, 0, اندازه(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, اندازه strport, "%d", port);
		اگر ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			اگر (errmsg != پوچ)
				*errmsg = ssh_gai_strerror(gaierr);
			اگر (reason != پوچ)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			بازگشت -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->port = port;
	cctx->ai = cctx->aitop;

	اگر ((sock = connect_next(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, port, strerror(errno));
		بازگشت -1;
	}

	بازگشت sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
ایستا Channel *
connect_to(ساختار ssh *ssh, ثابت نویسه *host, صحیح port,
    نویسه *ctype, نویسه *rname)
{
	ساختار channel_connect cctx;
	Channel *c;
	صحیح sock;

	memset(&cctx, 0, اندازه(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, پوچ, پوچ);
	اگر (sock == -1) {
		free_connect_ctx(&cctx);
		بازگشت پوچ;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(اندازه(cctx));
	memcpy(c->connect_ctx, &cctx, اندازه(cctx));

	بازگشت c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_address(ساختار ssh *ssh, ثابت نویسه *listen_host,
    u_short listen_port, نویسه *ctype, نویسه *rname)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	ساختار permission_set *pset = &sc->local_perms;
	u_int i;
	ساختار permission *perm;

	برای (i = 0; i < pset->رقم_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		اگر (open_listen_match_tcpip(perm,
		    listen_host, listen_port, 1)) {
			اگر (perm->downstream)
				بازگشت perm->downstream;
			اگر (perm->port_to_connect == 0)
				بازگشت rdynamic_connect_prepare(ssh,
				    ctype, rname);
			بازگشت connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_port);
	بازگشت پوچ;
}

Channel *
channel_connect_by_listen_path(ساختار ssh *ssh, ثابت نویسه *path,
    نویسه *ctype, نویسه *rname)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	ساختار permission_set *pset = &sc->local_perms;
	u_int i;
	ساختار permission *perm;

	برای (i = 0; i < pset->رقم_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		اگر (open_listen_match_streamlocal(perm, path)) {
			بازگشت connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    path);
	بازگشت پوچ;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_to_port(ساختار ssh *ssh, ثابت نویسه *host, u_short port,
    نویسه *ctype, نویسه *rname, صحیح *reason, ثابت نویسه **errmsg)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	ساختار permission_set *pset = &sc->local_perms;
	ساختار channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	صحیح sock;
	ساختار permission *perm;

	permit = pset->all_permitted;
	اگر (!permit) {
		برای (i = 0; i < pset->رقم_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			اگر (open_match(perm, host, port)) {
				permit = 1;
				بشکن;
			}
		}
	}

	اگر (pset->رقم_permitted_admin > 0) {
		permit_adm = 0;
		برای (i = 0; i < pset->رقم_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			اگر (open_match(perm, host, port)) {
				permit_adm = 1;
				بشکن;
			}
		}
	}

	اگر (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), host, port);
		اگر (reason != پوچ)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		بازگشت پوچ;
	}

	memset(&cctx, 0, اندازه(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	اگر (sock == -1) {
		free_connect_ctx(&cctx);
		بازگشت پوچ;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(اندازه(cctx));
	memcpy(c->connect_ctx, &cctx, اندازه(cctx));

	بازگشت c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_to_path(ساختار ssh *ssh, ثابت نویسه *path,
    نویسه *ctype, نویسه *rname)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	ساختار permission_set *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	ساختار permission *perm;

	permit = pset->all_permitted;
	اگر (!permit) {
		برای (i = 0; i < pset->رقم_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			اگر (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit = 1;
				بشکن;
			}
		}
	}

	اگر (pset->رقم_permitted_admin > 0) {
		permit_adm = 0;
		برای (i = 0; i < pset->رقم_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			اگر (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit_adm = 1;
				بشکن;
			}
		}
	}

	اگر (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", path);
		بازگشت پوچ;
	}
	بازگشت connect_to(ssh, path, PORT_STREAMLOCAL, ctype, rname);
}

تهی
channel_send_window_changes(ساختار ssh *ssh)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	ساختار winsize ws;
	صحیح r;
	u_int i;

	برای (i = 0; i < sc->channels_alloc; i++) {
		اگر (sc->channels[i] == پوچ || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			ادامه;
		اگر (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			ادامه;
		channel_request_start(ssh, i, "window-change", 0);
		اگر ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
ایستا Channel *
rdynamic_connect_prepare(ساختار ssh *ssh, نویسه *ctype, نویسه *rname)
{
	Channel *c;
	صحیح r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = 0;
	c->path = پوچ;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	بازگشت c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
ایستا صحیح
rdynamic_connect_finish(ساختار ssh *ssh, Channel *c)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	ساختار permission_set *pset = &sc->local_perms;
	ساختار permission *perm;
	ساختار channel_connect cctx;
	u_int i, permit_adm = 1;
	صحیح sock;

	اگر (pset->رقم_permitted_admin > 0) {
		permit_adm = 0;
		برای (i = 0; i < pset->رقم_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			اگر (open_match(perm, c->path, c->host_port)) {
				permit_adm = 1;
				بشکن;
			}
		}
	}
	اگر (!permit_adm) {
		debug_f("requested forward not permitted");
		بازگشت -1;
	}

	memset(&cctx, 0, اندازه(cctx));
	sock = connect_to_helper(ssh, c->path, c->host_port, SOCK_STREAM, پوچ,
	    پوچ, &cctx, پوچ, پوچ);
	اگر (sock == -1)
		free_connect_ctx(&cctx);
	وگرنه {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_FINISH;
		c->connect_ctx = xmalloc(اندازه(cctx));
		memcpy(c->connect_ctx, &cctx, اندازه(cctx));
		channel_register_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	بازگشت sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
صحیح
x11_create_display_inet(ساختار ssh *ssh, صحیح x11_display_offset,
    صحیح x11_use_localhost, صحیح single_connection,
    u_int *display_numberp, صحیح **chanids)
{
	Channel *nc = پوچ;
	صحیح display_عدد, sock, port;
	ساختار addrinfo hints, *ai, *aitop;
	نویسه strport[NI_MAXSERV];
	صحیح gaierr, n, رقم_socks = 0, socks[رقم_SOCKS];

	اگر (chanids == پوچ || x11_display_offset < 0 ||
	    x11_display_offset > UINT16_MAX - X11_BASE_PORT - MAX_DISPLAYS)
		بازگشت -1;

	برای (display_عدد = x11_display_offset;
	    display_عدد < x11_display_offset + MAX_DISPLAYS;
	    display_عدد++) {
		port = X11_BASE_PORT + display_عدد;
		memset(&hints, 0, اندازه(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, اندازه strport, "%d", port);
		اگر ((gaierr = getaddrinfo(پوچ, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			بازگشت -1;
		}
		برای (ai = aitop; ai; ai = ai->ai_next) {
			اگر (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				ادامه;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			اگر (sock == -1) {
				اگر ((errno != EINVAL) && (errno != EAFNOSUPPORT)
#ifdef EPFNOSUPPORT
				    && (errno != EPFNOSUPPORT)
#endif 
				    ) {
					error("socket: %.100s", strerror(errno));
					freeaddrinfo(aitop);
					بازگشت -1;
				} وگرنه {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					ادامه;
				}
			}
			اگر (ai->ai_family == AF_INET6)
				sock_set_v6only(sock);
			اگر (x11_use_localhost)
				set_reuseaddr(sock);
			اگر (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", port,
				    strerror(errno));
				close(sock);
				برای (n = 0; n < رقم_socks; n++)
					close(socks[n]);
				رقم_socks = 0;
				بشکن;
			}
			socks[رقم_socks++] = sock;
			اگر (رقم_socks == رقم_SOCKS)
				بشکن;
		}
		freeaddrinfo(aitop);
		اگر (رقم_socks > 0)
			بشکن;
	}
	اگر (display_عدد >= x11_display_offset + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		بازگشت -1;
	}
	/* Start listening for connections on the socket. */
	برای (n = 0; n < رقم_socks; n++) {
		sock = socks[n];
		اگر (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			بازگشت -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(رقم_socks + 1, اندازه(**chanids));
	برای (n = 0; n < رقم_socks; n++) {
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
	*display_numberp = display_عدد;
	بازگشت 0;
}

ایستا صحیح
connect_local_xsocket_path(ثابت نویسه *pathname)
{
	صحیح sock;
	ساختار sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	اگر (sock == -1) {
		error("socket: %.100s", strerror(errno));
		بازگشت -1;
	}
	memset(&addr, 0, اندازه(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, pathname, اندازه addr.sun_path);
	اگر (connect(sock, (ساختار sockaddr *)&addr, اندازه(addr)) == 0)
		بازگشت sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_path, strerror(errno));
	بازگشت -1;
}

ایستا صحیح
connect_local_xsocket(u_int dnr)
{
	نویسه buf[1024];
	snprintf(buf, اندازه buf, _PATH_UNIX_X, dnr);
	بازگشت connect_local_xsocket_path(buf);
}

#ifdef __APPLE__
ایستا صحیح
is_path_to_xsocket(ثابت نویسه *display, نویسه *path, size_t pathlen)
{
	ساختار stat sbuf;

	اگر (strlcpy(path, display, pathlen) >= pathlen) {
		error_f("display path too long");
		بازگشت 0;
	}
	اگر (display[0] != '/')
		بازگشت 0;
	اگر (stat(path, &sbuf) == 0) {
		بازگشت 1;
	} وگرنه {
		نویسه *dot = strrchr(path, '.');
		اگر (dot != پوچ) {
			*dot = '\0';
			اگر (stat(path, &sbuf) == 0) {
				بازگشت 1;
			}
		}
	}
	بازگشت 0;
}
#endif

صحیح
x11_connect_display(ساختار ssh *ssh)
{
	u_int display_عدد;
	ثابت نویسه *display;
	نویسه buf[1024], *cp;
	ساختار addrinfo hints, *ai, *aitop;
	نویسه strport[NI_MAXSERV];
	صحیح gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	اگر (!display) {
		error("DISPLAY not set.");
		بازگشت -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#ifdef __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		نویسه path[PATH_MAX];

		اگر (is_path_to_xsocket(display, path, اندازه(path))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_path(path);
			اگر (sock < 0)
				بازگشت -1;

			/* OK, we now have a connection to the display. */
			بازگشت sock;
		}
	}
#endif
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	اگر (strncmp(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		اگر (sscanf(strrchr(display, ':') + 1, "%u",
		    &display_عدد) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			بازگشت -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_عدد);
		اگر (sock < 0)
			بازگشت -1;

		/* OK, we now have a connection to the display. */
		بازگشت sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, اندازه(buf));
	cp = strchr(buf, ':');
	اگر (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		بازگشت -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	اگر (sscanf(cp + 1, "%u", &display_عدد) != 1 ||
	    display_عدد > UINT16_MAX - X11_BASE_PORT) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		بازگشت -1;
	}

	/* Look up the host address */
	memset(&hints, 0, اندازه(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, اندازه strport, "%u", X11_BASE_PORT + display_عدد);
	اگر ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		بازگشت -1;
	}
	برای (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		اگر (sock == -1) {
			debug2("socket: %.100s", strerror(errno));
			ادامه;
		}
		/* Connect it to the display. */
		اگر (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_BASE_PORT + display_عدد, strerror(errno));
			close(sock);
			ادامه;
		}
		/* Success */
		بشکن;
	}
	freeaddrinfo(aitop);
	اگر (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_BASE_PORT + display_عدد, strerror(errno));
		بازگشت -1;
	}
	set_nodelay(sock);
	بازگشت sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
تهی
x11_request_forwarding_with_spoofing(ساختار ssh *ssh, صحیح client_session_id,
    ثابت نویسه *disp, ثابت نویسه *proto, ثابت نویسه *data, صحیح want_reply)
{
	ساختار ssh_channels *sc = ssh->chanctxt;
	u_int data_len = (u_int) strlen(data) / 2;
	u_int i, مقدار;
	ثابت نویسه *cp;
	نویسه *new_data;
	صحیح r, screen_عدد;

	اگر (sc->x11_saved_display == پوچ)
		sc->x11_saved_display = xstrdup(disp);
	وگرنه اگر (strcmp(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		بازگشت;
	}

	cp = strchr(disp, ':');
	اگر (cp)
		cp = strchr(cp, '.');
	اگر (cp)
		screen_عدد = (u_int)strtonum(cp + 1, 0, 400, پوچ);
	وگرنه
		screen_عدد = 0;

	اگر (sc->x11_saved_proto == پوچ) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_data = xmalloc(data_len);
		برای (i = 0; i < data_len; i++) {
			اگر (sscanf(data + 2 * i, "%2x", &مقدار) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", data);
			}
			sc->x11_saved_data[i] = مقدار;
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
	اگر ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_data)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_عدد)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	آزاد(new_data);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
صحیح
x11_channel_used_recently(ساختار ssh *ssh) {
	u_int i;
	Channel *c;
	دوگانه lastused = 0;

	برای (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		اگر (c == پوچ || c->ctype == پوچ || c->lastused == 0.0 ||
		    strcmp(c->ctype, "x11-connection") != 0)
			ادامه;
		اگر (c->lastused > lastused)
			lastused = c->lastused;
	}
	بازگشت lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
