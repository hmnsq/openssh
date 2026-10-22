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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/ioctl.h>
#অন্তর্ভাব <sys/un.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/queue.h>

#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <arpa/inet.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <poll.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <termios.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "channels.h"
#অন্তর্ভাব "compat.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "match.h"

/* XXX remove once we're satisfied there's no lurking bugs */
/* #define DEBUG_CHANNEL_POLL 1 */

/* -- agent forwarding */
#define	অঙ্ক_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#define X11_BASE_PORT	6000
/* Maximum number of fake X11 displays to try. */
#define MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
প্রকারলেখ শূন্য chan_fn(কাঠামো ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
কাঠামো permission {
	অক্ষর *host_to_connect;		/* Connect to 'host'. */
	পূর্ণসংখ্যা port_to_connect;		/* Connect to 'port'. */
	অক্ষর *listen_host;		/* Remote side should listen address. */
	অক্ষর *listen_path;		/* Remote side should listen path. */
	পূর্ণসংখ্যা listen_port;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
কাঠামো channel_connect {
	অক্ষর *host;
	পূর্ণসংখ্যা port;
	কাঠামো addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
কাঠামো permission_set {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int অঙ্ক_permitted_user;
	কাঠামো permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int অঙ্ক_permitted_admin;
	কাঠামো permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	পূর্ণসংখ্যা all_permitted;
};

/* Used to record timeouts per channel type */
কাঠামো ssh_channel_timeout {
	অক্ষর *type_pattern;
	দ্বিগুণ timeout_secs;
};

/* Master structure for channels state */
কাঠামো ssh_channels {
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
	কাঠামো permission_set local_perms;
	কাঠামো permission_set remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	অক্ষর *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	অক্ষর *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	অক্ষর *x11_saved_তথ্য;
	u_int x11_saved_তথ্য_len;

	/* Deadline after which all X11 connections are refused */
	দ্বিগুণ x11_refuse_time;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_তথ্য;
	u_int x11_fake_তথ্য_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	পূর্ণসংখ্যা IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	পূর্ণসংখ্যা want_tcp_keepalive;

	/* Channel timeouts by type */
	কাঠামো ssh_channel_timeout *timeouts;
	আকার_t ntimeouts;
	/* Global timeout for all OPEN channels */
	দ্বিগুণ global_deadline;
	দ্বিগুণ lastused;
	/* pattern-lists used to classify channels as bulk */
	অক্ষর *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
স্থির শূন্য port_open_helper(কাঠামো ssh *ssh, Channel *c, অক্ষর *rtype);
স্থির ধ্রুবক অক্ষর *channel_rfwd_bind_host(ধ্রুবক অক্ষর *listen_host);

/* non-blocking connect helpers */
স্থির পূর্ণসংখ্যা connect_পরবর্তী(কাঠামো ssh *, কাঠামো channel_connect *);
স্থির Channel *rdynamic_connect_prepare(কাঠামো ssh *, অক্ষর *, অক্ষর *);
স্থির পূর্ণসংখ্যা rdynamic_connect_finish(কাঠামো ssh *, Channel *);

/* Setup helper */
স্থির শূন্য channel_handler_init(কাঠামো ssh_channels *sc);

/* -- channel core */

শূন্য
channel_init_channels(কাঠামো ssh *ssh)
{
	কাঠামো ssh_channels *sc;

	যদি ((sc = calloc(1, আকার(*sc))) == ফাঁকা)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, আকার(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(কাঠামো ssh *ssh, পূর্ণসংখ্যা id)
{
	Channel *c;

	যদি (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		ফেরত ফাঁকা;
	}
	c = ssh->chanctxt->channels[id];
	যদি (c == ফাঁকা) {
		logit_f("%d: bad id: channel free", id);
		ফেরত ফাঁকা;
	}
	ফেরত c;
}

Channel *
channel_by_remote_id(কাঠামো ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	জন্য (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		যদি (c != ফাঁকা && c->have_remote_id && c->remote_id == remote_id)
			ফেরত c;
	}
	ফেরত ফাঁকা;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(কাঠামো ssh *ssh, পূর্ণসংখ্যা id)
{
	Channel *c;

	যদি ((c = channel_by_id(ssh, id)) == ফাঁকা)
		ফেরত ফাঁকা;

	নির্বাচন (c->type) {
	ক্ষেত্র SSH_CHANNEL_X11_OPEN:
	ক্ষেত্র SSH_CHANNEL_LARVAL:
	ক্ষেত্র SSH_CHANNEL_CONNECTING:
	ক্ষেত্র SSH_CHANNEL_DYNAMIC:
	ক্ষেত্র SSH_CHANNEL_RDYNAMIC_OPEN:
	ক্ষেত্র SSH_CHANNEL_RDYNAMIC_FINISH:
	ক্ষেত্র SSH_CHANNEL_OPENING:
	ক্ষেত্র SSH_CHANNEL_OPEN:
	ক্ষেত্র SSH_CHANNEL_ABANDONED:
	ক্ষেত্র SSH_CHANNEL_MUX_PROXY:
		ফেরত c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	ফেরত ফাঁকা;
}

স্থির শূন্য
free_connect_ctx(কাঠামো channel_connect *cctx)
{
	মুক্ত(cctx->host);
	যদি (cctx->aitop) {
		যদি (cctx->aitop->ai_family == AF_UNIX)
			মুক্ত(cctx->aitop);
		অন্যথা
			freeaddrinfo(cctx->aitop);
	}
	memset(cctx, 0, আকার(*cctx));
}

স্থির শূন্য
channel_free_connect_ctx(Channel *c)
{
	যদি (c == ফাঁকা || c->connect_ctx == ফাঁকা)
		ফেরত;
	free_connect_ctx(c->connect_ctx);
	মুক্ত(c->connect_ctx);
	c->connect_ctx = ফাঁকা;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
শূন্য
channel_set_tcp_keepalives(কাঠামো ssh *ssh, পূর্ণসংখ্যা on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
শূন্য
channel_add_timeout(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *type_pattern,
    দ্বিগুণ timeout_secs)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;

	যদি (strcmp(type_pattern, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		ফেরত;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_pattern, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, আকার(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_pattern = xstrdup(type_pattern);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
শূন্য
channel_clear_timeouts(কাঠামো ssh *ssh)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	আকার_t i;

	debug3_f("clearing");
	জন্য (i = 0; i < sc->ntimeouts; i++)
		মুক্ত(sc->timeouts[i].type_pattern);
	মুক্ত(sc->timeouts);
	sc->timeouts = ফাঁকা;
	sc->ntimeouts = 0;
}

স্থির দ্বিগুণ
lookup_timeout(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *type)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	আকার_t i;

	জন্য (i = 0; i < sc->ntimeouts; i++) {
		যদি (match_pattern(type, sc->timeouts[i].type_pattern))
			ফেরত sc->timeouts[i].timeout_secs;
	}

	ফেরত 0;
}

স্থির শূন্য
channel_classify(কাঠামো ssh *ssh, Channel *c)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	ধ্রুবক অক্ষর *type = c->xctype == ফাঁকা ? c->ctype : c->xctype;
	ধ্রুবক পূর্ণসংখ্যা has_tty = c->isatty || c->remote_has_tty;
	ধ্রুবক অক্ষর *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != ফাঁকা && match_pattern_list(type, classifier, 0) == 1;
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
শূন্য
channel_set_xtype(কাঠামো ssh *ssh, পূর্ণসংখ্যা id, ধ্রুবক অক্ষর *xctype)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	যদি ((c = channel_by_id(ssh, id)) == ফাঁকা)
		fatal_f("missing channel %d", id);
	যদি (c->xctype != ফাঁকা)
		মুক্ত(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	দ্বিগুণ xtype_deadline = lookup_timeout(ssh, c->xctype);
	যদি (xtype_deadline != 0)
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
স্থির শূন্য
channel_set_used_time(কাঠামো ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	যদি (c != ফাঁকা)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
স্থির দ্বিগুণ
channel_get_expiry(কাঠামো ssh *ssh, Channel *c)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	দ্বিগুণ expiry = 0, channel_expiry;

	যদি (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	যদি (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		যদি (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	ফেরত expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
পূর্ণসংখ্যা
channel_has_bulk(কাঠামো ssh *ssh)
{
	ফেরত ssh->chanctxt != ফাঁকা && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
স্থির শূন্য
channel_register_fds(কাঠামো ssh *ssh, Channel *c, পূর্ণসংখ্যা rfd, পূর্ণসংখ্যা wfd, পূর্ণসংখ্যা efd,
    পূর্ণসংখ্যা extusage, পূর্ণসংখ্যা nonblock, পূর্ণসংখ্যা is_tty)
{
	পূর্ণসংখ্যা val;

	যদি (rfd != -1)
		(শূন্য)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	যদি (wfd != -1 && wfd != rfd)
		(শূন্য)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	যদি (efd != -1 && efd != rfd && efd != wfd)
		(শূন্য)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	যদি ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#endif

	/* enable nonblocking mode */
	c->restore_block = 0;
	যদি (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		যদি (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_block |= CHANNEL_RESTORE_RFD;
			set_nonblock(rfd);
		}
		যদি (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_block |= CHANNEL_RESTORE_WFD;
			set_nonblock(wfd);
		}
		যদি (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_block |= CHANNEL_RESTORE_EFD;
			set_nonblock(efd);
		}
	} অন্যথা যদি (nonblock) {
		যদি (rfd != -1)
			set_nonblock(rfd);
		যদি (wfd != -1)
			set_nonblock(wfd);
		যদি (efd != -1)
			set_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_set_used_time(ssh, ফাঁকা);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(কাঠামো ssh *ssh, অক্ষর *ctype, পূর্ণসংখ্যা type, পূর্ণসংখ্যা rfd, পূর্ণসংখ্যা wfd, পূর্ণসংখ্যা efd,
    u_int window, u_int maxpack, পূর্ণসংখ্যা extusage, ধ্রুবক অক্ষর *remote_name,
    পূর্ণসংখ্যা nonblock)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	u_int i, found = 0;
	Channel *c;
	পূর্ণসংখ্যা r;

	/* Try to find a free slot where to put the new channel. */
	জন্য (i = 0; i < sc->channels_alloc; i++) {
		যদি (sc->channels[i] == ফাঁকা) {
			/* Found a free slot. */
			found = i;
			বিরতি;
		}
	}
	যদি (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		found = sc->channels_alloc;
		যদি (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, আকার(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[found] = xcalloc(1, আকার(Channel));
	যদি ((c->প্রবেশ = sshbuf_new()) == ফাঁকা ||
	    (c->output = sshbuf_new()) == ফাঁকা ||
	    (c->extended = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_set_max_আকার(c->প্রবেশ, CHAN_প্রবেশ_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_প্রবেশ_OPEN;
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
	ফেরত c;
}

শূন্য
channel_set_tty(কাঠামো ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

পূর্ণসংখ্যা
channel_close_fd(কাঠামো ssh *ssh, Channel *c, পূর্ণসংখ্যা *fdp)
{
	পূর্ণসংখ্যা ret, fd = *fdp;

	যদি (fd == -1)
		ফেরত 0;

	/* restore blocking */
	যদি (*fdp == c->rfd &&
	    (c->restore_block & CHANNEL_RESTORE_RFD) != 0)
		(শূন্য)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	অন্যথা যদি (*fdp == c->wfd &&
	    (c->restore_block & CHANNEL_RESTORE_WFD) != 0)
		(শূন্য)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	অন্যথা যদি (*fdp == c->efd &&
	    (c->restore_block & CHANNEL_RESTORE_EFD) != 0)
		(শূন্য)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	যদি (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	যদি (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	যদি (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	যদি (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = close(fd);
	*fdp = -1; /* probably redundant */
	ফেরত ret;
}

/* Close all channel fd/socket. */
স্থির শূন্য
channel_close_fds(কাঠামো ssh *ssh, Channel *c)
{
	পূর্ণসংখ্যা sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	যদি (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	যদি (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	যদি (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

স্থির শূন্য
fwd_perm_clear(কাঠামো permission *perm)
{
	মুক্ত(perm->host_to_connect);
	মুক্ত(perm->listen_host);
	মুক্ত(perm->listen_path);
	memset(perm, 0, আকার(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
স্থির ধ্রুবক অক্ষর *
fwd_ident(পূর্ণসংখ্যা who, পূর্ণসংখ্যা where)
{
	যদি (who == FORWARD_ADM) {
		যদি (where == FORWARD_LOCAL)
			ফেরত "admin local";
		অন্যথা যদি (where == FORWARD_REMOTE)
			ফেরত "admin remote";
	} অন্যথা যদি (who == FORWARD_USER) {
		যদি (where == FORWARD_LOCAL)
			ফেরত "user local";
		অন্যথা যদি (where == FORWARD_REMOTE)
			ফেরত "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
স্থির কাঠামো permission_set *
permission_set_get(কাঠামো ssh *ssh, পূর্ণসংখ্যা where)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;

	নির্বাচন (where) {
	ক্ষেত্র FORWARD_LOCAL:
		ফেরত &sc->local_perms;
		বিরতি;
	ক্ষেত্র FORWARD_REMOTE:
		ফেরত &sc->remote_perms;
		বিরতি;
	পূর্বনির্ধারিত:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
স্থির শূন্য
permission_set_get_array(কাঠামো ssh *ssh, পূর্ণসংখ্যা who, পূর্ণসংখ্যা where,
    কাঠামো permission ***permpp, u_int **npermpp)
{
	কাঠামো permission_set *pset = permission_set_get(ssh, where);

	নির্বাচন (who) {
	ক্ষেত্র FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->অঙ্ক_permitted_user;
		বিরতি;
	ক্ষেত্র FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->অঙ্ক_permitted_admin;
		বিরতি;
	পূর্বনির্ধারিত:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
স্থির পূর্ণসংখ্যা
permission_set_add(কাঠামো ssh *ssh, পূর্ণসংখ্যা who, পূর্ণসংখ্যা where,
    ধ্রুবক অক্ষর *host_to_connect, পূর্ণসংখ্যা port_to_connect,
    ধ্রুবক অক্ষর *listen_host, ধ্রুবক অক্ষর *listen_path, পূর্ণসংখ্যা listen_port,
    Channel *downstream)
{
	কাঠামো permission **permp;
	u_int n, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);

	যদি (*npermp >= INT_MAX)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, আকার(**permp));
	n = (*npermp)++;
#define MAYBE_DUP(s) ((s == ফাঁকা) ? ফাঁকা : xstrdup(s))
	(*permp)[n].host_to_connect = MAYBE_DUP(host_to_connect);
	(*permp)[n].port_to_connect = port_to_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_path = MAYBE_DUP(listen_path);
	(*permp)[n].listen_port = listen_port;
	(*permp)[n].downstream = downstream;
#undef MAYBE_DUP
	ফেরত (পূর্ণসংখ্যা)n;
}

স্থির শূন্য
mux_remove_remote_forwardings(কাঠামো ssh *ssh, Channel *c)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	কাঠামো permission_set *pset = &sc->local_perms;
	কাঠামো permission *perm;
	পূর্ণসংখ্যা r;
	u_int i;

	জন্য (i = 0; i < pset->অঙ্ক_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		যদি (perm->downstream != c)
			চালু;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_port);
		যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_GLOBAL_REQUEST)) != 0 ||
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
শূন্য
channel_free(কাঠামো ssh *ssh, Channel *c)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	অক্ষর *s;
	u_int i, n;
	Channel *other;
	কাঠামো channel_confirm *cc;

	জন্য (n = 0, i = 0; i < sc->channels_alloc; i++) {
		যদি ((other = sc->channels[i]) == ফাঁকা)
			চালু;
		n++;
		/* detach from mux client and prepare for closing */
		যদি (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = ফাঁকা;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_প্রবেশ_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	যদি (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		মুক্ত(c->mux_ctx);
		c->mux_ctx = ফাঁকা;
	} অন্যথা যদি (c->type == SSH_CHANNEL_MUX_LISTENER) {
		মুক্ত(c->mux_ctx);
		c->mux_ctx = ফাঁকা;
	}

	যদি (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_message(ssh);
		debug3("channel %d: status: %s", c->self, s);
		মুক্ত(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->প্রবেশ);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->প্রবেশ = c->output = c->extended = ফাঁকা;
	মুক্ত(c->remote_name);
	c->remote_name = ফাঁকা;
	মুক্ত(c->path);
	c->path = ফাঁকা;
	মুক্ত(c->listening_addr);
	c->listening_addr = ফাঁকা;
	মুক্ত(c->xctype);
	c->xctype = ফাঁকা;
	channel_free_connect_ctx(c);
	যখন ((cc = TAILQ_FIRST(&c->status_confirms)) != ফাঁকা) {
		যদি (cc->abandon_cb != ফাঁকা)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->status_confirms, cc, entry);
		freezero(cc, আকার(*cc));
	}
	যদি (c->filter_cleanup != ফাঁকা && c->filter_ctx != ফাঁকা)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = ফাঁকা;
	freezero(c, আকার(*c));
}

শূন্য
channel_free_all(কাঠামো ssh *ssh)
{
	u_int i;
	কাঠামো ssh_channels *sc = ssh->chanctxt;

	জন্য (i = 0; i < sc->channels_alloc; i++)
		যদি (sc->channels[i] != ফাঁকা)
			channel_free(ssh, sc->channels[i]);

	মুক্ত(sc->channels);
	sc->channels = ফাঁকা;
	sc->channels_alloc = 0;

	মুক্ত(sc->x11_saved_display);
	sc->x11_saved_display = ফাঁকা;

	মুক্ত(sc->x11_saved_proto);
	sc->x11_saved_proto = ফাঁকা;

	মুক্ত(sc->x11_saved_তথ্য);
	sc->x11_saved_তথ্য = ফাঁকা;
	sc->x11_saved_তথ্য_len = 0;

	মুক্ত(sc->x11_fake_তথ্য);
	sc->x11_fake_তথ্য = ফাঁকা;
	sc->x11_fake_তথ্য_len = 0;
}

শূন্য
channel_free_channels(কাঠামো ssh *ssh)
{
	কাঠামো ssh_channels *sc;

	যদি (ssh == ফাঁকা || ssh->chanctxt == ফাঁকা)
		ফেরত;
	channel_free_all(ssh);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_REMOTE);
	sc = ssh->chanctxt;
	মুক্ত(sc->bulk_classifier_tty);
	মুক্ত(sc->bulk_classifier_notty);
	মুক্ত(sc->channel_pre);
	মুক্ত(sc->channel_post);
	freezero(sc, আকার(*sc));
	ssh->chanctxt = ফাঁকা;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
শূন্য
channel_close_all(কাঠামো ssh *ssh)
{
	u_int i;

	জন্য (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		যদি (ssh->chanctxt->channels[i] != ফাঁকা)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
শূন্য
channel_stop_listening(কাঠামো ssh *ssh)
{
	u_int i;
	Channel *c;

	জন্য (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		যদি (c != ফাঁকা) {
			নির্বাচন (c->type) {
			ক্ষেত্র SSH_CHANNEL_AUTH_SOCKET:
			ক্ষেত্র SSH_CHANNEL_PORT_LISTENER:
			ক্ষেত্র SSH_CHANNEL_RPORT_LISTENER:
			ক্ষেত্র SSH_CHANNEL_X11_LISTENER:
			ক্ষেত্র SSH_CHANNEL_UNIX_LISTENER:
			ক্ষেত্র SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				বিরতি;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
পূর্ণসংখ্যা
channel_not_very_much_buffered_তথ্য(কাঠামো ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	জন্য (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		যদি (c == ফাঁকা || c->type != SSH_CHANNEL_OPEN)
			চালু;
		যদি (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			ফেরত 0;
		}
	}
	ফেরত 1;
}

/* Returns true if any channel is still open. */
পূর্ণসংখ্যা
channel_still_open(কাঠামো ssh *ssh)
{
	u_int i;
	Channel *c;

	জন্য (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		যদি (c == ফাঁকা)
			চালু;
		নির্বাচন (c->type) {
		ক্ষেত্র SSH_CHANNEL_X11_LISTENER:
		ক্ষেত্র SSH_CHANNEL_PORT_LISTENER:
		ক্ষেত্র SSH_CHANNEL_RPORT_LISTENER:
		ক্ষেত্র SSH_CHANNEL_MUX_LISTENER:
		ক্ষেত্র SSH_CHANNEL_CLOSED:
		ক্ষেত্র SSH_CHANNEL_AUTH_SOCKET:
		ক্ষেত্র SSH_CHANNEL_DYNAMIC:
		ক্ষেত্র SSH_CHANNEL_RDYNAMIC_OPEN:
		ক্ষেত্র SSH_CHANNEL_CONNECTING:
		ক্ষেত্র SSH_CHANNEL_ZOMBIE:
		ক্ষেত্র SSH_CHANNEL_ABANDONED:
		ক্ষেত্র SSH_CHANNEL_UNIX_LISTENER:
		ক্ষেত্র SSH_CHANNEL_RUNIX_LISTENER:
			চালু;
		ক্ষেত্র SSH_CHANNEL_LARVAL:
			চালু;
		ক্ষেত্র SSH_CHANNEL_OPENING:
		ক্ষেত্র SSH_CHANNEL_OPEN:
		ক্ষেত্র SSH_CHANNEL_RDYNAMIC_FINISH:
		ক্ষেত্র SSH_CHANNEL_X11_OPEN:
		ক্ষেত্র SSH_CHANNEL_MUX_CLIENT:
		ক্ষেত্র SSH_CHANNEL_MUX_PROXY:
			ফেরত 1;
		পূর্বনির্ধারিত:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ফেরত 0;
}

/* Returns true if a channel with a TTY is open. */
পূর্ণসংখ্যা
channel_tty_open(কাঠামো ssh *ssh)
{
	u_int i;
	Channel *c;

	জন্য (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		যদি (c == ফাঁকা || c->type != SSH_CHANNEL_OPEN)
			চালু;
		যদি (c->client_tty)
			ফেরত 1;
	}
	ফেরত 0;
}

/* Returns the id of an open channel suitable for keepaliving */
পূর্ণসংখ্যা
channel_find_open(কাঠামো ssh *ssh)
{
	u_int i;
	Channel *c;

	জন্য (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		যদি (c == ফাঁকা || !c->have_remote_id)
			চালু;
		নির্বাচন (c->type) {
		ক্ষেত্র SSH_CHANNEL_CLOSED:
		ক্ষেত্র SSH_CHANNEL_DYNAMIC:
		ক্ষেত্র SSH_CHANNEL_RDYNAMIC_OPEN:
		ক্ষেত্র SSH_CHANNEL_RDYNAMIC_FINISH:
		ক্ষেত্র SSH_CHANNEL_X11_LISTENER:
		ক্ষেত্র SSH_CHANNEL_PORT_LISTENER:
		ক্ষেত্র SSH_CHANNEL_RPORT_LISTENER:
		ক্ষেত্র SSH_CHANNEL_MUX_LISTENER:
		ক্ষেত্র SSH_CHANNEL_MUX_CLIENT:
		ক্ষেত্র SSH_CHANNEL_MUX_PROXY:
		ক্ষেত্র SSH_CHANNEL_OPENING:
		ক্ষেত্র SSH_CHANNEL_CONNECTING:
		ক্ষেত্র SSH_CHANNEL_ZOMBIE:
		ক্ষেত্র SSH_CHANNEL_ABANDONED:
		ক্ষেত্র SSH_CHANNEL_UNIX_LISTENER:
		ক্ষেত্র SSH_CHANNEL_RUNIX_LISTENER:
			চালু;
		ক্ষেত্র SSH_CHANNEL_LARVAL:
		ক্ষেত্র SSH_CHANNEL_AUTH_SOCKET:
		ক্ষেত্র SSH_CHANNEL_OPEN:
		ক্ষেত্র SSH_CHANNEL_X11_OPEN:
			ফেরত i;
		পূর্বনির্ধারিত:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ফেরত -1;
}

/* Returns the state of the channel's extended usage flag */
ধ্রুবক অক্ষর *
channel_format_extended_usage(ধ্রুবক Channel *c)
{
	যদি (c->efd == -1)
		ফেরত "closed";

	নির্বাচন (c->extended_usage) {
	ক্ষেত্র CHAN_EXTENDED_WRITE:
		ফেরত "write";
	ক্ষেত্র CHAN_EXTENDED_READ:
		ফেরত "read";
	ক্ষেত্র CHAN_EXTENDED_IGNORE:
		ফেরত "ignore";
	পূর্বনির্ধারিত:
		ফেরত "UNKNOWN";
	}
}

স্থির অক্ষর *
channel_format_status(ধ্রুবক Channel *c)
{
	অক্ষর *ret = ফাঁকা;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != ফাঁকা ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != ফাঁকা ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->প্রবেশ),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_child_id ? "c" : "nc", c->ctl_child_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	ফেরত ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
অক্ষর *
channel_open_message(কাঠামো ssh *ssh)
{
	কাঠামো sshbuf *buf;
	Channel *c;
	u_int i;
	পূর্ণসংখ্যা r;
	অক্ষর *cp, *ret;

	যদি ((buf = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	জন্য (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		যদি (c == ফাঁকা)
			চালু;
		নির্বাচন (c->type) {
		ক্ষেত্র SSH_CHANNEL_X11_LISTENER:
		ক্ষেত্র SSH_CHANNEL_PORT_LISTENER:
		ক্ষেত্র SSH_CHANNEL_RPORT_LISTENER:
		ক্ষেত্র SSH_CHANNEL_CLOSED:
		ক্ষেত্র SSH_CHANNEL_AUTH_SOCKET:
		ক্ষেত্র SSH_CHANNEL_ZOMBIE:
		ক্ষেত্র SSH_CHANNEL_ABANDONED:
		ক্ষেত্র SSH_CHANNEL_MUX_LISTENER:
		ক্ষেত্র SSH_CHANNEL_UNIX_LISTENER:
		ক্ষেত্র SSH_CHANNEL_RUNIX_LISTENER:
			চালু;
		ক্ষেত্র SSH_CHANNEL_LARVAL:
		ক্ষেত্র SSH_CHANNEL_OPENING:
		ক্ষেত্র SSH_CHANNEL_CONNECTING:
		ক্ষেত্র SSH_CHANNEL_DYNAMIC:
		ক্ষেত্র SSH_CHANNEL_RDYNAMIC_OPEN:
		ক্ষেত্র SSH_CHANNEL_RDYNAMIC_FINISH:
		ক্ষেত্র SSH_CHANNEL_OPEN:
		ক্ষেত্র SSH_CHANNEL_X11_OPEN:
		ক্ষেত্র SSH_CHANNEL_MUX_PROXY:
		ক্ষেত্র SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_status(c);
			যদি ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				মুক্ত(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			মুক্ত(cp);
			চালু;
		পূর্বনির্ধারিত:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	যদি ((ret = sshbuf_dup_string(buf)) == ফাঁকা)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	ফেরত ret;
}

শূন্য
channel_report_open(কাঠামো ssh *ssh, পূর্ণসংখ্যা level)
{
	অক্ষর *open, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, আকার(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (long)getpid());
	open = oopen = channel_open_message(ssh);
	যখন ((cp = strsep(&open, "\r\n")) != ফাঁকা) {
		যদি (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	মুক্ত(oopen);
}

স্থির শূন্য
open_preamble(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *where, Channel *c, ধ্রুবক অক্ষর *type)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

শূন্য
channel_send_open(কাঠামো ssh *ssh, পূর্ণসংখ্যা id)
{
	Channel *c = channel_lookup(ssh, id);
	পূর্ণসংখ্যা r;

	যদি (c == ফাঁকা) {
		logit("channel_send_open: %d: bad id", id);
		ফেরত;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	যদি ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

শূন্য
channel_request_start(কাঠামো ssh *ssh, পূর্ণসংখ্যা id, ধ্রুবক অক্ষর *service,
    পূর্ণসংখ্যা wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	পূর্ণসংখ্যা r;

	যদি (c == ফাঁকা) {
		logit_f("%d: unknown channel id", id);
		ফেরত;
	}
	যদি (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

শূন্য
channel_register_status_confirm(কাঠামো ssh *ssh, পূর্ণসংখ্যা id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, শূন্য *ctx)
{
	কাঠামো channel_confirm *cc;
	Channel *c;

	যদি ((c = channel_lookup(ssh, id)) == ফাঁকা)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, আকার(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->status_confirms, cc, entry);
}

শূন্য
channel_register_open_confirm(কাঠামো ssh *ssh, পূর্ণসংখ্যা id,
    channel_open_fn *fn, শূন্য *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	যদি (c == ফাঁকা) {
		logit_f("%d: bad id", id);
		ফেরত;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

শূন্য
channel_register_cleanup(কাঠামো ssh *ssh, পূর্ণসংখ্যা id,
    channel_callback_fn *fn, পূর্ণসংখ্যা do_close)
{
	Channel *c = channel_by_id(ssh, id);

	যদি (c == ফাঁকা) {
		logit_f("%d: bad id", id);
		ফেরত;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

শূন্য
channel_cancel_cleanup(কাঠামো ssh *ssh, পূর্ণসংখ্যা id)
{
	Channel *c = channel_by_id(ssh, id);

	যদি (c == ফাঁকা) {
		logit_f("%d: bad id", id);
		ফেরত;
	}
	c->detach_user = ফাঁকা;
	c->detach_close = 0;
}

শূন্য
channel_register_filter(কাঠামো ssh *ssh, পূর্ণসংখ্যা id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, শূন্য *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	যদি (c == ফাঁকা) {
		logit_f("%d: bad id", id);
		ফেরত;
	}
	c->প্রবেশ_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

শূন্য
channel_set_fds(কাঠামো ssh *ssh, পূর্ণসংখ্যা id, পূর্ণসংখ্যা rfd, পূর্ণসংখ্যা wfd, পূর্ণসংখ্যা efd,
    পূর্ণসংখ্যা extusage, পূর্ণসংখ্যা nonblock, পূর্ণসংখ্যা is_tty, u_int window_max)
{
	Channel *c = channel_lookup(ssh, id);
	পূর্ণসংখ্যা r;

	যদি (c == ফাঁকা || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	যদি (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_register_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_set_used_time(ssh, c);
	c->local_window = c->local_window_max = window_max;

	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_CHANNEL_WINDOW_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

স্থির শূন্য
channel_pre_listener(কাঠামো ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

স্থির শূন্য
channel_pre_connecting(কাঠামো ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

স্থির শূন্য
channel_pre_open(কাঠামো ssh *ssh, Channel *c)
{
	c->io_want = 0;
	যদি (c->istate == CHAN_প্রবেশ_OPEN &&
	    c->remote_window > 0 &&
	    sshbuf_len(c->প্রবেশ) < c->remote_window &&
	    sshbuf_check_reserve(c->প্রবেশ, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	যদি (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		যদি (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} অন্যথা যদি (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			যদি (CHANNEL_EFD_OUTPUT_ACTIVE(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			অন্যথা
				chan_obuf_empty(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	যদি (c->efd != -1 && !(c->istate == CHAN_প্রবেশ_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		যদি (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		অন্যথা যদি (c->efd != -1 && !(c->flags & CHAN_EOF_SENT) &&
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
স্থির পূর্ণসংখ্যা
x11_open_helper(কাঠামো ssh *ssh, কাঠামো sshbuf *b)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, তথ্য_len;

	যদি (sc->x11_saved_proto == ফাঁকা) {
		error("X11 forwarding opened before X11 forwarding requested");
		ফেরত -1;
	}

	/* Is this being called after the refusal deadline? */
	যদি (sc->x11_refuse_time != 0.0 &&
	    monotime_double() >= sc->x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		ফেরত -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	যদি (sshbuf_len(b) < 12)
		ফেরত 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	যদি (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		তথ্য_len = 256 * ucp[8] + ucp[9];
	} অন্যথা যদি (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		তথ্য_len = ucp[8] + 256 * ucp[9];
	} অন্যথা {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		ফেরত -1;
	}

	/* Check if the whole packet is in buffer. */
	যদি (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((তথ্য_len + 3) & ~3))
		ফেরত 0;

	/* Check if authentication protocol matches. */
	যদি (proto_len != strlen(sc->x11_saved_proto) ||
	    memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		ফেরত -1;
	}
	/* Check if authentication data matches our fake data. */
	যদি (তথ্য_len != sc->x11_fake_তথ্য_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_তথ্য, sc->x11_fake_তথ্য_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		ফেরত -1;
	}
	/* Check fake data length */
	যদি (sc->x11_fake_তথ্য_len != sc->x11_saved_তথ্য_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_তথ্য_len, sc->x11_saved_তথ্য_len);
		ফেরত -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	memcpy(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_তথ্য, sc->x11_saved_তথ্য_len);
	ফেরত 1;
}

শূন্য
channel_force_close(কাঠামো ssh *ssh, Channel *c, পূর্ণসংখ্যা abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	যদি (c->istate == CHAN_প্রবেশ_OPEN)
		chan_read_failed(ssh, c);
	যদি (c->istate == CHAN_প্রবেশ_WAIT_DRAIN) {
		sshbuf_reset(c->প্রবেশ);
		chan_ibuf_empty(ssh, c);
	}
	যদি (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	যদি (c->detach_user)
		c->detach_user(ssh, c->self, 1, ফাঁকা);
	যদি (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	যদি (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

স্থির শূন্য
channel_pre_x11_open(কাঠামো ssh *ssh, Channel *c)
{
	পূর্ণসংখ্যা ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	যদি (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		channel_pre_open(ssh, c);
	} অন্যথা যদি (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

স্থির শূন্য
channel_pre_mux_client(কাঠামো ssh *ssh, Channel *c)
{
	c->io_want = 0;
	যদি (c->istate == CHAN_প্রবেশ_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->প্রবেশ, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	যদি (c->istate == CHAN_প্রবেশ_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->প্রবেশ);
		chan_ibuf_empty(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	যদি (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		যদি (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		অন্যথা যদি (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_empty(ssh, c);
	}
}

স্থির অন্তঃরেখ পূর্ণসংখ্যা
socks_decode_error(Channel *c, পূর্ণসংখ্যা status, ধ্রুবক অক্ষর *func, ধ্রুবক অক্ষর *বার্তা)
{
	যদি (status == SSH_ERR_MESSAGE_INCOMPLETE)
		ফেরত 0;
	অন্যথা {
		debug_r(status, "%s: channel %d: decode %s",
		    func, c->self, বার্তা);
		ফেরত -1;
	}
}

/* try to decode a socks4 header */
স্থির পূর্ণসংখ্যা
channel_decode_socks4(Channel *c, কাঠামো sshbuf *প্রবেশ, কাঠামো sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_port;
	অক্ষর *user = ফাঁকা, *host = ফাঁকা;
	পূর্ণসংখ্যা success = -1, socks4a = 0, r;
	কাঠামো sshbuf *b = ফাঁকা;

	যদি (sshbuf_len(প্রবেশ) < 9)
		ফেরত 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	যদি ((b = sshbuf_fromb(প্রবেশ)) == ফাঁকা)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	যদি ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, আকার(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, ফাঁকা)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		যাও out;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	যদি (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		যদি ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, ফাঁকা)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			যাও out;
		}
		socks4a = 1;
	} অন্যথা {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	যদি ((r = sshbuf_consume_upto_child(প্রবেশ, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (পূর্ণসংখ্যা)socks_cmd,
	    host, dest_port);
	যদি (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		যাও out;
	}
	মুক্ত(c->path);
	c->path = host;
	host = ফাঁকা; /* transferred */
	c->host_port = dest_port;

	/* Reply to the SOCKS4 client */
	যদি ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
	    (r = sshbuf_put_u8(output, 90)) != 0 ||	/* cd: req granted */
	    (r = sshbuf_put_u16(output, 0)) != 0 ||	/* port: ignored */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0) /* ignored */
		fatal_fr(r, "channel %d: compose reply", c->self);

	/* success */
	success = 1;
 out:
	sshbuf_free(b);
	মুক্ত(user);
	মুক্ত(host);
	ফেরত success;
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
স্থির পূর্ণসংখ্যা
channel_socks5_check_auth(Channel *c, কাঠামো sshbuf *b, কাঠামো sshbuf *প্রবেশ,
    কাঠামো sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, method;
	পূর্ণসংখ্যা r;
	u_int i, found;

	/* format: ver | nmethods | methods */
	যদি ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		ফেরত socks_decode_error(c, r, __func__, "version");
	যদি (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	যদি ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		ফেরত socks_decode_error(c, r, __func__, "methods");
	জন্য (found = i = 0; i < nmethods; i++) {
		যদি ((r = sshbuf_get_u8(b, &method)) != 0)
			ফেরত socks_decode_error(c, r, __func__, "method");
		যদি (method == SSH_SOCKS5_NOAUTH)
			found = 1;
	}
	যদি (!found) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		ফেরত -1;
	}
	/* Consume completed request */
	যদি ((r = sshbuf_consume_upto_child(প্রবেশ, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	যদি ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
channel_decode_socks5(Channel *c, কাঠামো sshbuf *প্রবেশ, কাঠামো sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_port;
	অক্ষর dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	পূর্ণসংখ্যা r, success = -1;;
	কাঠামো sshbuf *b = ফাঁকা;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	যদি ((b = sshbuf_fromb(প্রবেশ)) == ফাঁকা)
		fatal_f("sshbuf_fromb failed");

	যদি (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		যদি ((r = channel_socks5_check_auth(c, b, প্রবেশ, output)) != 1) {
			success = r;
			যাও out;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	যদি ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		যাও out;
	}
	যদি (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	যদি ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		যাও out;
	}

	যদি (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		যাও out;
	}

	নির্বাচন (socks_atyp) {
	ক্ষেত্র SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		বিরতি;
	ক্ষেত্র SSH_SOCKS5_DOMAIN:
		যদি ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			যাও out;
		}
		af = -1;
		বিরতি;
	ক্ষেত্র SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		বিরতি;
	পূর্বনির্ধারিত:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		যাও out;
	}
	যদি ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		যাও out;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	যদি ((r = sshbuf_consume_upto_child(প্রবেশ, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	মুক্ত(c->path);
	c->path = ফাঁকা;
	যদি (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->path = xstrdup(dest_addr);
	অন্যথা {
		যদি (inet_ntop(af, dest_addr, ntop, আকার(ntop)) == ফাঁকা)
			ফেরত -1;
		c->path = xstrdup(ntop);
	}
	c->host_port = dest_port;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->path, c->host_port, socks_cmd);

	/* Reply */
	যদি ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/* version */
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
	ফেরত success;
}

Channel *
channel_connect_stdio_fwd(কাঠামো ssh *ssh,
    ধ্রুবক অক্ষর *host_to_connect, পূর্ণসংখ্যা port_to_connect,
    পূর্ণসংখ্যা in, পূর্ণসংখ্যা out, পূর্ণসংখ্যা nonblock)
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

	ফেরত c;
}

/* dynamic port forwarding */
স্থির শূন্য
channel_pre_dynamic(কাঠামো ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	পূর্ণসংখ্যা r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->প্রবেশ);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	যদি (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		ফেরত;
	}
	/* try to guess the protocol */
	যদি ((r = sshbuf_peek_u8(c->প্রবেশ, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	নির্বাচন (ver) {
	ক্ষেত্র 0x04:
		ret = channel_decode_socks4(c, c->প্রবেশ, c->output);
		বিরতি;
	ক্ষেত্র 0x05:
		ret = channel_decode_socks5(c, c->প্রবেশ, c->output);
		বিরতি;
	পূর্বনির্ধারিত:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		বিরতি;
	}
	যদি (ret < 0) {
		chan_mark_dead(ssh, c);
	} অন্যথা যদি (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		যদি (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} অন্যথা {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		port_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
স্থির শূন্য
rdynamic_close(কাঠামো ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
স্থির শূন্য
channel_before_prepare_io_rdynamic(কাঠামো ssh *ssh, Channel *c)
{
	ধ্রুবক u_char *p;
	u_int have, len;
	পূর্ণসংখ্যা r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	যদি (c->flags & CHAN_EOF_RCVD) {
		যদি ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		ফেরত;
	}
	/* check if the fixed size part of the packet is in buffer. */
	যদি (have < 3)
		ফেরত;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	নির্বাচন (p[0]) {
	ক্ষেত্র 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->প্রবেশ);
		বিরতি;
	ক্ষেত্র 0x05:
		ret = channel_decode_socks5(c, c->output, c->প্রবেশ);
		বিরতি;
	পূর্বনির্ধারিত:
		ret = -1;
		বিরতি;
	}
	যদি (ret < 0) {
		rdynamic_close(ssh, c);
	} অন্যথা যদি (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->প্রবেশ);
		যদি (len > 0 && len < c->remote_window) {
			যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_CHANNEL_তথ্য)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->প্রবেশ)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			যদি ((r = sshbuf_consume(c->প্রবেশ, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_window -= len;
		}
	} অন্যথা যদি (rdynamic_connect_finish(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
স্থির শূন্য
channel_post_x11_listener(কাঠামো ssh *ssh, Channel *c)
{
	Channel *nc;
	কাঠামো sockaddr_storage addr;
	পূর্ণসংখ্যা r, newsock, oerrno, remote_port;
	socklen_t addrlen;
	অক্ষর buf[16384], *remote_ipaddr;

	যদি ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ফেরত;

	debug("X11 connection requested.");
	addrlen = আকার(addr);
	newsock = accept(c->sock, (কাঠামো sockaddr *)&addr, &addrlen);
	যদি (c->single_connection) {
		oerrno = errno;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		errno = oerrno;
	}
	যদি (newsock == -1) {
		যদি (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		যদি (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ফেরত;
	}
	set_nodelay(newsock);
	যদি (ssh->chanctxt->want_tcp_keepalive)
		set_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_port = get_peer_port(newsock);
	snprintf(buf, আকার buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_port);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	যদি ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_port)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	যদি ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	মুক্ত(remote_ipaddr);
}

স্থির শূন্য
port_open_helper(কাঠামো ssh *ssh, Channel *c, অক্ষর *rtype)
{
	অক্ষর *local_ipaddr = get_local_ipaddr(c->sock);
	পূর্ণসংখ্যা local_port = c->sock == -1 ? 65536 : get_local_port(c->sock);
	অক্ষর *remote_ipaddr = get_peer_ipaddr(c->sock);
	পূর্ণসংখ্যা remote_port = get_peer_port(c->sock);
	পূর্ণসংখ্যা r;

	যদি (remote_port == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		মুক্ত(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_port = 65535;
	}

	মুক্ত(c->remote_name);
	xasprintf(&c->remote_name,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d to %.100s port %d",
	    rtype, c->listening_port, c->path, c->host_port,
	    remote_ipaddr, remote_port, local_ipaddr, local_port);

	open_preamble(ssh, __func__, c, rtype);
	যদি (strcmp(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		যদি ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} অন্যথা যদি (strcmp(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		যদি ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} অন্যথা যদি (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		যদি ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} অন্যথা {
		/* listen address, port */
		যদি ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	যদি (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		যদি ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} অন্যথা {
		/* originator host and port */
		যদি ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	যদি ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	মুক্ত(remote_ipaddr);
	মুক্ত(local_ipaddr);
}

শূন্য
channel_set_x11_refuse_time(কাঠামো ssh *ssh, দ্বিগুণ refuse_time)
{
	ssh->chanctxt->x11_refuse_time = refuse_time;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
স্থির শূন্য
channel_post_port_listener(কাঠামো ssh *ssh, Channel *c)
{
	Channel *nc;
	কাঠামো sockaddr_storage addr;
	পূর্ণসংখ্যা newsock, nextstate;
	socklen_t addrlen;
	অক্ষর *rtype;

	যদি ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ফেরত;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_port, c->path, c->host_port);

	যদি (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} অন্যথা যদি (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} অন্যথা যদি (c->host_port == PORT_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} অন্যথা যদি (c->host_port == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} অন্যথা {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = আকার(addr);
	newsock = accept(c->sock, (কাঠামো sockaddr *)&addr, &addrlen);
	যদি (newsock == -1) {
		যদি (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		যদি (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ফেরত;
	}
	যদি (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		set_nodelay(newsock);
		যদি (ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_port = c->listening_port;
	nc->host_port = c->host_port;
	যদি (c->path != ফাঁকা)
		nc->path = xstrdup(c->path);

	যদি (nextstate != SSH_CHANNEL_DYNAMIC)
		port_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
স্থির শূন্য
channel_post_auth_listener(কাঠামো ssh *ssh, Channel *c)
{
	Channel *nc;
	পূর্ণসংখ্যা r, newsock;
	কাঠামো sockaddr_storage addr;
	socklen_t addrlen;

	যদি ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ফেরত;

	addrlen = আকার(addr);
	newsock = accept(c->sock, (কাঠামো sockaddr *)&addr, &addrlen);
	যদি (newsock == -1) {
		error("accept from auth socket: %.100s", strerror(errno));
		যদি (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ফেরত;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	যদি ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

স্থির শূন্য
channel_post_connecting(কাঠামো ssh *ssh, Channel *c)
{
	পূর্ণসংখ্যা err = 0, sock, isopen, r;
	socklen_t sz = আকার(err);

	যদি ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		ফেরত;
	যদি (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	যদি (c->connect_ctx == ফাঁকা)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_FINISH);

	যদি (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = errno;
		error("getsockopt SO_ERROR failed");
	}

	যদি (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		যদি (isopen) {
			/* no message necessary */
		} অন্যথা {
			যদি ((r = sshpkt_start(ssh,
			    SSH2_বার্তা_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		ফেরত;
	}
	যদি (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		ফেরত;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, strerror(err));

	/* Try next address, if any */
	যদি ((sock = connect_পরবর্তী(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		যদি (isopen) {
			rdynamic_close(ssh, c);
		} অন্যথা {
			যদি ((r = sshpkt_start(ssh,
			    SSH2_বার্তা_CHANNEL_OPEN_FAILURE)) != 0 ||
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

স্থির পূর্ণসংখ্যা
channel_handle_rfd(কাঠামো ssh *ssh, Channel *c)
{
	অক্ষর buf[CHAN_RBUF];
	ssize_t len;
	পূর্ণসংখ্যা r, force;
	আকার_t nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	পূর্ণসংখ্যা pty_zeroread = 0;

#ifdef PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#endif

	force = c->isatty && c->detach_close && c->istate != CHAN_প্রবেশ_CLOSED;

	যদি (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		ফেরত 1;
	যদি ((avail = sshbuf_avail(c->প্রবেশ)) == 0)
		ফেরত 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	যদি (!pty_zeroread && c->প্রবেশ_filter == ফাঁকা && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		যদি (c->type == SSH_CHANNEL_OPEN) {
			যদি ((have = sshbuf_len(c->প্রবেশ)) >= c->remote_window)
				ফেরত 1; /* shouldn't happen */
			যদি (maxlen > c->remote_window - have)
				maxlen = c->remote_window - have;
		}
		যদি (maxlen > avail)
			maxlen = avail;
		যদি ((r = sshbuf_read(c->rfd, c->প্রবেশ, maxlen, &nr)) != 0) {
			যদি (errno == EINTR || (!force &&
			    (errno == EAGAIN || errno == EWOULDBLOCK)))
				ফেরত 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			যাও rfail;
		}
		যদি (nr != 0)
			channel_set_used_time(ssh, c);
		ফেরত 1;
	}

	errno = 0;
	len = পঠ(c->rfd, buf, আকার(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	যদি (pty_zeroread && len == 0 && errno != 0)
		len = -1;
	যদি (len == -1 && (errno == EINTR ||
	    ((errno == EAGAIN || errno == EWOULDBLOCK) && !force)))
		ফেরত 1;
	যদি (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : strerror(errno));
 rfail:
		যদি (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			ফেরত -1;
		} অন্যথা {
			chan_read_failed(ssh, c);
		}
		ফেরত -1;
	}
	channel_set_used_time(ssh, c);
	যদি (c->প্রবেশ_filter != ফাঁকা) {
		যদি (c->প্রবেশ_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} অন্যথা যদি (c->datagram) {
		যদি ((r = sshbuf_put_string(c->প্রবেশ, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} অন্যথা যদি ((r = sshbuf_put(c->প্রবেশ, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
channel_handle_wfd(কাঠামো ssh *ssh, Channel *c)
{
	কাঠামো termios tio;
	u_char *তথ্য = ফাঁকা, *buf; /* XXX const; need filter API change */
	আকার_t dlen, olen = 0;
	পূর্ণসংখ্যা r, len;

	যদি ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		ফেরত 1;
	যদি (sshbuf_len(c->output) == 0)
		ফেরত 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	যদি (c->output_filter != ফাঁকা) {
		যদি ((buf = c->output_filter(ssh, c, &তথ্য, &dlen)) == ফাঁকা) {
			debug2("channel %d: filter stops", c->self);
			যদি (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			অন্যথা
				chan_write_failed(ssh, c);
			ফেরত -1;
		}
	} অন্যথা যদি (c->datagram) {
		যদি ((r = sshbuf_get_string(c->output, &তথ্য, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = তথ্য;
	} অন্যথা {
		buf = তথ্য = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	যদি (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = লিখ(c->wfd, buf, dlen);
		মুক্ত(তথ্য);
		যদি (len == -1 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK))
			ফেরত 1;
		যদি (len <= 0)
			যাও write_fail;
		যাও out;
	}

#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	যদি (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#endif

	len = লিখ(c->wfd, buf, dlen);
	যদি (len == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		ফেরত 1;
	যদি (len <= 0) {
 write_fail:
		যদি (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			ফেরত -1;
		} অন্যথা {
			chan_write_failed(ssh, c);
		}
		ফেরত -1;
	}
	channel_set_used_time(ssh, c);
#ifndef BROKEN_TCGETATTR_ICANON
	যদি (c->isatty && dlen >= 1 && buf[0] != '\r') {
		যদি (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			যদি ((r = sshpkt_বার্তা_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#endif /* BROKEN_TCGETATTR_ICANON */
	যদি ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 out:
	c->local_consumed += olen - sshbuf_len(c->output);

	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
channel_handle_efd_write(কাঠামো ssh *ssh, Channel *c)
{
	পূর্ণসংখ্যা r;
	ssize_t len;

	যদি ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		ফেরত 1;
	যদি (sshbuf_len(c->extended) == 0)
		ফেরত 1;

	len = লিখ(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	যদি (len == -1 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		ফেরত 1;
	যদি (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} অন্যথা {
		যদি ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_set_used_time(ssh, c);
	}
	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
channel_handle_efd_read(কাঠামো ssh *ssh, Channel *c)
{
	অক্ষর buf[CHAN_RBUF];
	ssize_t len;
	পূর্ণসংখ্যা r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_প্রবেশ_CLOSED;

	যদি (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		ফেরত 1;

	len = পঠ(c->efd, buf, আকার(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	যদি (len == -1 && (errno == EINTR || ((errno == EAGAIN ||
	    errno == EWOULDBLOCK) && !force)))
		ফেরত 1;
	যদি (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		ফেরত 1;
	}
	channel_set_used_time(ssh, c);
	যদি (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	অন্যথা যদি ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
channel_handle_efd(কাঠামো ssh *ssh, Channel *c)
{
	যদি (c->efd == -1)
		ফেরত 1;

	/** XXX handle drain efd, too */

	যদি (c->extended_usage == CHAN_EXTENDED_WRITE)
		ফেরত channel_handle_efd_write(ssh, c);
	অন্যথা যদি (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		ফেরত channel_handle_efd_read(ssh, c);

	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
channel_check_window(কাঠামো ssh *ssh, Channel *c)
{
	পূর্ণসংখ্যা r;

	যদি (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD)) &&
	    ((c->local_window_max - c->local_window >
	    c->local_maxpacket*3) ||
	    c->local_window < c->local_window_max/2) &&
	    c->local_consumed > 0) {
		যদি (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		যদি ((r = sshpkt_start(ssh,
		    SSH2_বার্তা_CHANNEL_WINDOW_ADJUST)) != 0 ||
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
	ফেরত 1;
}

স্থির শূন্য
channel_post_open(কাঠামো ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_window(ssh, c);
}

স্থির u_int
read_mux(কাঠামো ssh *ssh, Channel *c, u_int need)
{
	অক্ষর buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	পূর্ণসংখ্যা r;

	যদি (sshbuf_len(c->প্রবেশ) < need) {
		rlen = need - sshbuf_len(c->প্রবেশ);
		len = পঠ(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		যদি (len == -1 && (errno == EINTR || errno == EAGAIN))
			ফেরত sshbuf_len(c->প্রবেশ);
		যদি (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			ফেরত 0;
		} অন্যথা যদি ((r = sshbuf_put(c->প্রবেশ, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	ফেরত sshbuf_len(c->প্রবেশ);
}

স্থির শূন্য
channel_post_mux_client_read(কাঠামো ssh *ssh, Channel *c)
{
	u_int need;

	যদি ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		ফেরত;
	যদি (c->istate != CHAN_প্রবেশ_OPEN && c->istate != CHAN_প্রবেশ_WAIT_DRAIN)
		ফেরত;
	যদি (c->mux_pause)
		ফেরত;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	যদি (read_mux(ssh, c, 4) < 4) /* read header */
		ফেরত;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->প্রবেশ));
#define CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	যদি (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		ফেরত;
	}
	যদি (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		ফেরত;
	যদি (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		ফেরত;
	}
}

স্থির শূন্য
channel_post_mux_client_write(কাঠামো ssh *ssh, Channel *c)
{
	ssize_t len;
	পূর্ণসংখ্যা r;

	যদি ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		ফেরত;
	যদি (sshbuf_len(c->output) == 0)
		ফেরত;

	len = লিখ(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	যদি (len == -1 && (errno == EINTR || errno == EAGAIN))
		ফেরত;
	যদি (len <= 0) {
		chan_mark_dead(ssh, c);
		ফেরত;
	}
	যদি ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

স্থির শূন্য
channel_post_mux_client(কাঠামো ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

স্থির শূন্য
channel_post_mux_listener(কাঠামো ssh *ssh, Channel *c)
{
	Channel *nc;
	কাঠামো sockaddr_storage addr;
	socklen_t addrlen;
	পূর্ণসংখ্যা newsock;
	uid_t euid;
	gid_t egid;

	যদি ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ফেরত;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, আকার(addr));
	addrlen = আকার(addr);
	যদি ((newsock = accept(c->sock, (কাঠামো sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", strerror(errno));
		যদি (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ফেরত;
	}

	যদি (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", strerror(errno));
		close(newsock);
		ফেরত;
	}
	যদি ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		ফেরত;
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

স্থির শূন্য
channel_handler_init(কাঠামো ssh_channels *sc)
{
	chan_fn **pre, **post;

	যদি ((pre = calloc(SSH_CHANNEL_MAX_TYPE, আকার(*pre))) == ফাঁকা ||
	    (post = calloc(SSH_CHANNEL_MAX_TYPE, আকার(*post))) == ফাঁকা)
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
স্থির শূন্য
channel_garbage_collect(কাঠামো ssh *ssh, Channel *c)
{
	যদি (c == ফাঁকা)
		ফেরত;
	যদি (c->detach_user != ফাঁকা) {
		যদি (!chan_is_dead(ssh, c, c->detach_close))
			ফেরত;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, ফাঁকা);
		/* if we still have a callback */
		যদি (c->detach_user != ফাঁকা)
			ফেরত;
		debug2("channel %d: gc: user detached", c->self);
	}
	যদি (!chan_is_dead(ssh, c, 1))
		ফেরত;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

গণনা channel_table { CHAN_PRE, CHAN_POST };

স্থির শূন্য
channel_handler(কাঠামো ssh *ssh, পূর্ণসংখ্যা table, কাঠামো timespec *timeout)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = table == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	দ্বিগুণ now;

	now = monotime_double();
	জন্য (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		যদি (c == ফাঁকা)
			চালু;
		/* Count open channels in bulk state */
		যদি (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		যদি (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			চালু;
		যদি (c->delayed) {
			যদি (table == CHAN_PRE)
				c->delayed = 0;
			অন্যথা
				চালু;
		}
		যদি (ftab[c->type] != ফাঁকা) {
			যদি (table == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				দ্বিগুণ deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} অন্যথা যদি (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				যদি (timeout != ফাঁকা &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} অন্যথা যদি (timeout != ফাঁকা) {
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
স্থির শূন্য
channel_before_prepare_io(কাঠামো ssh *ssh)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	জন্য (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		যদি (c == ফাঁকা)
			চালু;
		যদি (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

স্থির শূন্য
dump_channel_poll(ধ্রুবক অক্ষর *func, ধ্রুবক অক্ষর *what, Channel *c,
    u_int pollfd_offset, কাঠামো pollfd *pfd)
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
স্থির শূন্য
channel_prepare_pollfd(Channel *c, u_int *পরবর্তী_pollfd,
    কাঠামো pollfd *pfd, u_int npfd)
{
	u_int ev, p = *পরবর্তী_pollfd;

	যদি (c == ফাঁকা)
		ফেরত;
	যদি (p + 4 > npfd) {
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
	যদি (c->rfd != -1) {
		ev = 0;
		যদি ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		যদি (c->wfd == c->rfd) {
			যদি ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		যদি (c->efd == c->rfd) {
			যদি ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			যদি ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		যদি (c->sock == c->rfd) {
			যদি ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			যদি ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		যদি (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	যদি (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		যদি ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		যদি (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	যদি (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		যদি ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		যদি ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		যদি (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	যদি (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		যদি ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		যদি ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		যদি (ev != 0) {
			c->pfds[3] = p;
			pfd[p].fd = c->sock;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "sock", c, p, &pfd[p]);
			p++;
		}
	}
	*পরবর্তী_pollfd = p;
}

/* * Allocate/prepare poll structure */
শূন্য
channel_prepare_poll(কাঠামো ssh *ssh, কাঠামো pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, কাঠামো timespec *timeout)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	জন্য (i = 0; i < sc->channels_alloc; i++) {
		যদি (sc->channels[i] == ফাঁকা)
			চালু;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	যদি (sc->channels_alloc >= (INT_MAX / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	যদি (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, আকার(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	যদি (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	জন্য (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

স্থির শূন্য
fd_ready(Channel *c, পূর্ণসংখ্যা p, কাঠামো pollfd *pfds, u_int npfd, পূর্ণসংখ্যা fd,
    ধ্রুবক অক্ষর *what, u_int revents_mask, u_int ready)
{
	কাঠামো pollfd *pfd = &pfds[p];

	যদি (fd == -1)
		ফেরত;
	যদি (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	যদি (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	যদি ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	যদি ((pfd->revents & (revents_mask|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
শূন্য
channel_after_poll(কাঠামো ssh *ssh, কাঠামো pollfd *pfd, u_int npfd)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	u_int i;
	পূর্ণসংখ্যা p;
	Channel *c;

#ifdef DEBUG_CHANNEL_POLL
	জন্য (p = 0; p < (পূর্ণসংখ্যা)npfd; p++) {
		যদি (pfd[p].revents == 0)
			চালু;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#endif

	/* Convert pollfd into c->io_ready */
	জন্য (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		যদি (c == ফাঁকা)
			চালু;
		/* if rfd is shared with efd/sock then wfd should be too */
		যদি (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		যদি (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			যদি (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			যদি (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			যদি (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		যদি (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		যদি (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		যদি (c->sock != -1 && c->sock != c->rfd &&
		    (p = c->pfds[3]) != -1) {
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockr", POLLIN, SSH_CHAN_IO_SOCK_R);
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockw", POLLOUT, SSH_CHAN_IO_SOCK_W);
			dump_channel_poll(__func__, "sock", c, p, pfd);
		}
	}
	channel_handler(ssh, CHAN_POST, ফাঁকা);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
স্থির পূর্ণসংখ্যা
channel_output_poll_প্রবেশ_open(কাঠামো ssh *ssh, Channel *c)
{
	আকার_t len, plen;
	ধ্রুবক u_char *pkt;
	পূর্ণসংখ্যা r;

	যদি ((len = sshbuf_len(c->প্রবেশ)) == 0) {
		যদি (c->istate == CHAN_প্রবেশ_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			যদি (CHANNEL_EFD_প্রবেশ_ACTIVE(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			অন্যথা
				chan_ibuf_empty(ssh, c);
		}
		ফেরত 0;
	}

	যদি (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	যদি (c->datagram) {
		/* Check datagram will fit; drop if not */
		যদি ((r = sshbuf_get_string_direct(c->প্রবেশ, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		যদি (plen > c->remote_window || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			ফেরত 0;
		}
		/* Enqueue it */
		যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_CHANNEL_তথ্য)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_window -= plen;
		ফেরত 1;
	}

	/* Enqueue packet for buffered data. */
	যদি (len > c->remote_window)
		len = c->remote_window;
	যদি (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	যদি (len == 0)
		ফেরত 0;
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_CHANNEL_তথ্য)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->প্রবেশ), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	যদি ((r = sshbuf_consume(c->প্রবেশ, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	ফেরত 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
স্থির পূর্ণসংখ্যা
channel_output_poll_extended_read(কাঠামো ssh *ssh, Channel *c)
{
	আকার_t len;
	পূর্ণসংখ্যা r;

	যদি ((len = sshbuf_len(c->extended)) == 0)
		ফেরত 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_window, sshbuf_len(c->extended), c->extended_usage);
	যদি (len > c->remote_window)
		len = c->remote_window;
	যদি (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	যদি (len == 0)
		ফেরত 0;
	যদি (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_CHANNEL_EXTENDED_তথ্য)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_তথ্য_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	যদি ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	ফেরত 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
পূর্ণসংখ্যা
channel_output_poll(কাঠামো ssh *ssh)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	পূর্ণসংখ্যা ret = 0;

	জন্য (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		যদি (c == ফাঁকা)
			চালু;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		যদি (c->type != SSH_CHANNEL_OPEN)
			চালু;
		যদি ((c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			চালু;
		}

		/* Get the amount of buffered data for this channel. */
		যদি (c->istate == CHAN_প্রবেশ_OPEN ||
		    c->istate == CHAN_প্রবেশ_WAIT_DRAIN)
			ret |= channel_output_poll_প্রবেশ_open(ssh, c);
		/* Send extended data, i.e. stderr */
		যদি (!(c->flags & CHAN_EOF_SENT) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	ফেরত ret;
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
পূর্ণসংখ্যা
channel_proxy_downstream(কাঠামো ssh *ssh, Channel *downstream)
{
	Channel *c = ফাঁকা;
	কাঠামো sshbuf *original = ফাঁকা, *modified = ফাঁকা;
	ধ্রুবক u_char *cp;
	অক্ষর *ctype = ফাঁকা, *listen_host = ফাঁকা;
	u_char type;
	আকার_t have;
	পূর্ণসংখ্যা ret = -1, r;
	u_int id, remote_id, listen_port;

	/* sshbuf_dump(downstream->input, stderr); */
	যদি ((r = sshbuf_get_string_direct(downstream->প্রবেশ, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		ফেরত -1;
	}
	যদি (have < 2) {
		error_f("short message");
		ফেরত -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	যদি (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	নির্বাচন (type) {
	ক্ষেত্র SSH2_বার্তা_CHANNEL_OPEN:
		যদি ((original = sshbuf_from(cp, have)) == ফাঁকা ||
		    (modified = sshbuf_new()) == ফাঁকা) {
			error_f("alloc");
			যাও out;
		}
		যদি ((r = sshbuf_get_cstring(original, &ctype, ফাঁকা)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			যাও out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		যদি ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			যাও out;
		}
		বিরতি;
	ক্ষেত্র SSH2_বার্তা_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		যদি ((original = sshbuf_from(cp, have)) == ফাঁকা ||
		    (modified = sshbuf_new()) == ফাঁকা) {
			error_f("alloc");
			যাও out;
		}
		যদি ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			যাও out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, "mux-down-connect", 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;
		c->remote_id = remote_id;
		c->have_remote_id = 1;
		যদি ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			যাও out;
		}
		বিরতি;
	ক্ষেত্র SSH2_বার্তা_GLOBAL_REQUEST:
		যদি ((original = sshbuf_from(cp, have)) == ফাঁকা) {
			error_f("alloc");
			যাও out;
		}
		যদি ((r = sshbuf_get_cstring(original, &ctype, ফাঁকা)) != 0) {
			error_fr(r, "parse");
			যাও out;
		}
		যদি (strcmp(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			যাও out;
		}
		যদি ((r = sshbuf_get_u8(original, ফাঁকা)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, ফাঁকা)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_port)) != 0) {
			error_fr(r, "parse");
			যাও out;
		}
		যদি (listen_port > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_port);
			যাও out;
		}
		/* Record that connection to this host/port is permitted. */
		permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, ফাঁকা, (পূর্ণসংখ্যা)listen_port, downstream);
		বিরতি;
	ক্ষেত্র SSH2_বার্তা_CHANNEL_CLOSE:
		যদি (have < 4)
			বিরতি;
		remote_id = PEEK_U32(cp);
		যদি ((c = channel_by_remote_id(ssh, remote_id)) != ফাঁকা) {
			যদি (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			অন্যথা
				c->flags |= CHAN_CLOSE_SENT;
		}
		বিরতি;
	}
	যদি (modified) {
		যদি ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			যাও out;
		}
	} অন্যথা {
		যদি ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			যাও out;
		}
	}
	ret = 0;
 out:
	মুক্ত(ctype);
	মুক্ত(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	ফেরত ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
পূর্ণসংখ্যা
channel_proxy_upstream(Channel *c, পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	কাঠামো sshbuf *b = ফাঁকা;
	Channel *downstream;
	ধ্রুবক u_char *cp = ফাঁকা;
	আকার_t len;
	পূর্ণসংখ্যা r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	যদি (c == ফাঁকা || c->type != SSH_CHANNEL_MUX_PROXY)
		ফেরত 0;
	যদি ((downstream = c->mux_ctx) == ফাঁকা)
		ফেরত 0;
	নির্বাচন (type) {
	ক্ষেত্র SSH2_বার্তা_CHANNEL_CLOSE:
	ক্ষেত্র SSH2_বার্তা_CHANNEL_তথ্য:
	ক্ষেত্র SSH2_বার্তা_CHANNEL_EOF:
	ক্ষেত্র SSH2_বার্তা_CHANNEL_EXTENDED_তথ্য:
	ক্ষেত্র SSH2_বার্তা_CHANNEL_OPEN_CONFIRMATION:
	ক্ষেত্র SSH2_বার্তা_CHANNEL_OPEN_FAILURE:
	ক্ষেত্র SSH2_বার্তা_CHANNEL_WINDOW_ADJUST:
	ক্ষেত্র SSH2_বার্তা_CHANNEL_SUCCESS:
	ক্ষেত্র SSH2_বার্তা_CHANNEL_FAILURE:
	ক্ষেত্র SSH2_বার্তা_CHANNEL_REQUEST:
		বিরতি;
	পূর্বনির্ধারিত:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		ফেরত 0;
	}
	যদি ((b = sshbuf_new()) == ফাঁকা) {
		error_f("alloc reply");
		যাও out;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	যদি (cp == ফাঁকা) {
		error_f("no packet");
		যাও out;
	}
	/* translate id and send to muxclient */
	যদি ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		যাও out;
	}
	/* sshbuf_dump(b, stderr); */
	যদি (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 out:
	/* update state */
	নির্বাচন (type) {
	ক্ষেত্র SSH2_বার্তা_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		যদি (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		বিরতি;
	ক্ষেত্র SSH2_বার্তা_CHANNEL_CLOSE:
		যদি (c->flags & CHAN_CLOSE_SENT)
			channel_free(ssh, c);
		অন্যথা
			c->flags |= CHAN_CLOSE_RCVD;
		বিরতি;
	}
	sshbuf_free(b);
	ফেরত 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
স্থির পূর্ণসংখ্যা
channel_parse_id(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *where, ধ্রুবক অক্ষর *what)
{
	uint32_t id;
	পূর্ণসংখ্যা r;

	যদি ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	যদি (id > INT_MAX) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	ফেরত (পূর্ণসংখ্যা)id;
}

/* Lookup a channel from an ID in the current packet */
স্থির Channel *
channel_from_packet_id(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *where, ধ্রুবক অক্ষর *what)
{
	পূর্ণসংখ্যা id = channel_parse_id(ssh, where, what);
	Channel *c;

	যদি ((c = channel_lookup(ssh, id)) == ফাঁকা) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	ফেরত c;
}

পূর্ণসংখ্যা
channel_প্রবেশ_তথ্য(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	ধ্রুবক u_char *তথ্য;
	আকার_t তথ্য_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	পূর্ণসংখ্যা r;

	যদি (channel_proxy_upstream(c, type, seq, ssh))
		ফেরত 0;

	/* Ignore any data for non-open channels (might happen on close) */
	যদি (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_FINISH &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		ফেরত 0;

	/* Get the data. */
	যদি ((r = sshpkt_get_string_direct(ssh, &তথ্য, &তথ্য_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = তথ্য_len;
	যদি (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	যদি (c->ostate != CHAN_OUTPUT_OPEN) {
		যদি (win_len > c->local_window)
			c->local_window = 0;
		অন্যথা
			c->local_window -= win_len;
		c->local_consumed += win_len;
		ফেরত 0;
	}

	যদি (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		ফেরত 0;
	}
	যদি (win_len > c->local_window) {
		u_int delta = win_len - c->local_window;

		যদি (c->local_window_exceeded > UINT_MAX - delta)
			c->local_window_exceeded = UINT_MAX;
		অন্যথা
			c->local_window_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_window,
		    c->local_window_max, c->local_window_exceeded);
		c->local_window = 0;
		/* Allow 10% grace before bringing the hammer down */
		যদি (c->local_window_exceeded > (c->local_window_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} অন্যথা {
		c->local_window -= win_len;
		c->local_window_exceeded = 0;
	}

	যদি (c->datagram) {
		যদি ((r = sshbuf_put_string(c->output, তথ্য, তথ্য_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} অন্যথা যদি ((r = sshbuf_put(c->output, তথ্য, তথ্য_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	ফেরত 0;
}

পূর্ণসংখ্যা
channel_প্রবেশ_extended_তথ্য(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	ধ্রুবক u_char *তথ্য;
	আকার_t তথ্য_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	পূর্ণসংখ্যা r;

	যদি (channel_proxy_upstream(c, type, seq, ssh))
		ফেরত 0;
	যদি (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		ফেরত 0;
	}
	যদি (c->flags & CHAN_EOF_RCVD) {
		যদি (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		অন্যথা
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	যদি ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	যদি (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_তথ্য_STDERR) {
		logit("channel %d: bad ext data", c->self);
		ফেরত 0;
	}
	যদি ((r = sshpkt_get_string_direct(ssh, &তথ্য, &তথ্য_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	যদি (তথ্য_len > c->local_window) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, তথ্য_len, c->local_window);
		ফেরত 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, তথ্য_len);
	/* XXX sshpkt_getb? */
	যদি ((r = sshbuf_put(c->extended, তথ্য, তথ্য_len)) != 0)
		error_fr(r, "append");
	c->local_window -= তথ্য_len;
	ফেরত 0;
}

পূর্ণসংখ্যা
channel_প্রবেশ_ieof(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	পূর্ণসংখ্যা r;

        যদি ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	যদি (channel_proxy_upstream(c, type, seq, ssh))
		ফেরত 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	যদি (c->force_drain && c->istate == CHAN_প্রবেশ_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_প্রবেশ_WAIT_DRAIN;
		যদি (sshbuf_len(c->প্রবেশ) == 0)
			chan_ibuf_empty(ssh, c);
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
channel_প্রবেশ_oclose(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	পূর্ণসংখ্যা r;

	যদি (channel_proxy_upstream(c, type, seq, ssh))
		ফেরত 0;
        যদি ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	ফেরত 0;
}

পূর্ণসংখ্যা
channel_প্রবেশ_open_confirmation(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_window, remote_maxpacket;
	পূর্ণসংখ্যা r;

	যদি (channel_proxy_upstream(c, type, seq, ssh))
		ফেরত 0;
	যদি (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	যদি ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
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
	যদি (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_set_used_time(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_window, c->remote_maxpacket);
	ফেরত 0;
}

স্থির অক্ষর *
reason2txt(পূর্ণসংখ্যা reason)
{
	নির্বাচন (reason) {
	ক্ষেত্র SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		ফেরত "administratively prohibited";
	ক্ষেত্র SSH2_OPEN_CONNECT_FAILED:
		ফেরত "connect failed";
	ক্ষেত্র SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		ফেরত "unknown channel type";
	ক্ষেত্র SSH2_OPEN_RESOURCE_SHORTAGE:
		ফেরত "resource shortage";
	}
	ফেরত "unknown reason";
}

পূর্ণসংখ্যা
channel_প্রবেশ_open_failure(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	অক্ষর *বার্তা = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি (channel_proxy_upstream(c, type, seq, ssh))
		ফেরত 0;
	যদি (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	যদি ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	যদি ((r = sshpkt_get_cstring(ssh, &বার্তা, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, ফাঁকা, ফাঁকা)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), বার্তা ? ": ": "", বার্তা ? বার্তা : "");
	মুক্ত(বার্তা);
	যদি (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	ফেরত 0;
}

পূর্ণসংখ্যা
channel_প্রবেশ_window_adjust(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	পূর্ণসংখ্যা r;

	যদি ((c = channel_lookup(ssh, id)) == ফাঁকা) {
		logit("Received window adjust for non-open channel %d.", id);
		ফেরত 0;
	}

	যদি (channel_proxy_upstream(c, type, seq, ssh))
		ফেরত 0;
	যদি ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	যদি ((new_rwin = c->remote_window + adjust) < c->remote_window) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_window);
	}
	c->remote_window = new_rwin;
	ফেরত 0;
}

পূর্ণসংখ্যা
channel_প্রবেশ_status_confirm(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	কাঠামো channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_set_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	যদি ((c = channel_lookup(ssh, id)) == ফাঁকা) {
		logit_f("%d: unknown", id);
		ফেরত 0;
	}
	যদি (channel_proxy_upstream(c, type, seq, ssh))
		ফেরত 0;
        যদি (sshpkt_get_end(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	যদি ((cc = TAILQ_FIRST(&c->status_confirms)) == ফাঁকা)
		ফেরত 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->status_confirms, cc, entry);
	freezero(cc, আকার(*cc));
	ফেরত 0;
}

/* -- tcp forwarding */

শূন্য
channel_set_af(কাঠামো ssh *ssh, পূর্ণসংখ্যা af)
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
স্থির ধ্রুবক অক্ষর *
channel_fwd_bind_addr(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *listen_addr, পূর্ণসংখ্যা *wildcardp,
    পূর্ণসংখ্যা is_client, কাঠামো ForwardOptions *fwd_opts)
{
	ধ্রুবক অক্ষর *addr = ফাঁকা;
	পূর্ণসংখ্যা wildcard = 0;

	যদি (listen_addr == ফাঁকা) {
		/* No address specified: default to gateway_ports setting */
		যদি (fwd_opts->gateway_ports)
			wildcard = 1;
	} অন্যথা যদি (fwd_opts->gateway_ports || is_client) {
		যদি (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			যদি (*listen_addr != '\0' &&
			    strcmp(listen_addr, "0.0.0.0") != 0 &&
			    strcmp(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} অন্যথা যদি (strcmp(listen_addr, "localhost") != 0 ||
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
	} অন্যথা যদি (strcmp(listen_addr, "127.0.0.1") == 0 ||
	    strcmp(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	যদি (wildcardp != ফাঁকা)
		*wildcardp = wildcard;
	ফেরত addr;
}

স্থির পূর্ণসংখ্যা
channel_setup_fwd_listener_tcpip(কাঠামো ssh *ssh, পূর্ণসংখ্যা type,
    কাঠামো Forward *fwd, পূর্ণসংখ্যা *allocated_listen_port,
    কাঠামো ForwardOptions *fwd_opts)
{
	Channel *c;
	পূর্ণসংখ্যা sock, r, success = 0, wildcard = 0, is_client;
	কাঠামো addrinfo hints, *ai, *aitop;
	ধ্রুবক অক্ষর *host, *addr;
	অক্ষর ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_PORT_LISTENER);

	যদি (is_client && fwd->connect_path != ফাঁকা) {
		host = fwd->connect_path;
	} অন্যথা {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		যদি (host == ফাঁকা) {
			error("No forward host name.");
			ফেরত 0;
		}
		যদি (strlen(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			ফেরত 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == ফাঁকা) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, আকার(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, আকার strport, "%d", fwd->listen_port);
	যদি ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		যদি (addr == ফাঁকা) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} অন্যথা {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		ফেরত 0;
	}
	যদি (allocated_listen_port != ফাঁকা)
		*allocated_listen_port = 0;
	জন্য (ai = aitop; ai; ai = ai->ai_next) {
		নির্বাচন (ai->ai_family) {
		ক্ষেত্র AF_INET:
			lport_p = &((কাঠামো sockaddr_in *)ai->ai_addr)->
			    sin_port;
			বিরতি;
		ক্ষেত্র AF_INET6:
			lport_p = &((কাঠামো sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			বিরতি;
		পূর্বনির্ধারিত:
			চালু;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		যদি (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 && allocated_listen_port != ফাঁকা &&
		    *allocated_listen_port > 0)
			*lport_p = htons(*allocated_listen_port);

		যদি (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, আকার(ntop),
		    strport, আকার(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			চালু;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		যদি (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			চালু;
		}

		set_reuseaddr(sock);
		যদি (ai->ai_family == AF_INET6)
			sock_set_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		যদি (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			যদি (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));
			অন্যথা
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));

			close(sock);
			চালু;
		}
		/* Start listening for connections on the socket. */
		যদি (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			close(sock);
			চালু;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		যদি (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 &&
		    allocated_listen_port != ফাঁকা &&
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
		c->listening_addr = addr == ফাঁকা ? ফাঁকা : xstrdup(addr);
		যদি (fwd->listen_port == 0 && allocated_listen_port != ফাঁকা &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_port = *allocated_listen_port;
		অন্যথা
			c->listening_port = fwd->listen_port;
		success = 1;
	}
	যদি (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_port);
	freeaddrinfo(aitop);
	ফেরত success;
}

স্থির পূর্ণসংখ্যা
channel_setup_fwd_listener_streamlocal(কাঠামো ssh *ssh, পূর্ণসংখ্যা type,
    কাঠামো Forward *fwd, কাঠামো ForwardOptions *fwd_opts)
{
	কাঠামো sockaddr_un sunaddr;
	ধ্রুবক অক্ষর *path;
	Channel *c;
	পূর্ণসংখ্যা port, sock;
	mode_t omask;

	নির্বাচন (type) {
	ক্ষেত্র SSH_CHANNEL_UNIX_LISTENER:
		যদি (fwd->connect_path != ফাঁকা) {
			যদি (strlen(fwd->connect_path) > আকার(sunaddr.sun_path)) {
				error("Local connecting path too long: %s",
				    fwd->connect_path);
				ফেরত 0;
			}
			path = fwd->connect_path;
			port = PORT_STREAMLOCAL;
		} অন্যথা {
			যদি (fwd->connect_host == ফাঁকা) {
				error("No forward host name.");
				ফেরত 0;
			}
			যদি (strlen(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				ফেরত 0;
			}
			path = fwd->connect_host;
			port = fwd->connect_port;
		}
		বিরতি;
	ক্ষেত্র SSH_CHANNEL_RUNIX_LISTENER:
		path = fwd->listen_path;
		port = PORT_STREAMLOCAL;
		বিরতি;
	পূর্বনির্ধারিত:
		error_f("unexpected channel type %d", type);
		ফেরত 0;
	}

	যদি (fwd->listen_path == ফাঁকা) {
		error("No forward path name.");
		ফেরত 0;
	}
	যদি (strlen(fwd->listen_path) > আকার(sunaddr.sun_path)) {
		error("Local listening path too long: %s", fwd->listen_path);
		ফেরত 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_path);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_mask);
	sock = unix_listener(fwd->listen_path, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	যদি (sock < 0)
		ফেরত 0;

	debug("Local forwarding listening on path %s.", fwd->listen_path);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->path = xstrdup(path);
	c->host_port = port;
	c->listening_port = PORT_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_path);
	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
channel_cancel_rport_listener_tcpip(কাঠামো ssh *ssh,
    ধ্রুবক অক্ষর *host, u_short port)
{
	u_int i;
	পূর্ণসংখ্যা found = 0;

	জন্য (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		যদি (c == ফাঁকা || c->type != SSH_CHANNEL_RPORT_LISTENER)
			চালু;
		যদি (strcmp(c->path, host) == 0 && c->listening_port == port) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ফেরত found;
}

স্থির পূর্ণসংখ্যা
channel_cancel_rport_listener_streamlocal(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *path)
{
	u_int i;
	পূর্ণসংখ্যা found = 0;

	জন্য (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		যদি (c == ফাঁকা || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			চালু;
		যদি (c->path == ফাঁকা)
			চালু;
		যদি (strcmp(c->path, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ফেরত found;
}

পূর্ণসংখ্যা
channel_cancel_rport_listener(কাঠামো ssh *ssh, কাঠামো Forward *fwd)
{
	যদি (fwd->listen_path != ফাঁকা) {
		ফেরত channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} অন্যথা {
		ফেরত channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port);
	}
}

স্থির পূর্ণসংখ্যা
channel_cancel_lport_listener_tcpip(কাঠামো ssh *ssh,
    ধ্রুবক অক্ষর *lhost, u_short lport, পূর্ণসংখ্যা cport,
    কাঠামো ForwardOptions *fwd_opts)
{
	u_int i;
	পূর্ণসংখ্যা found = 0;
	ধ্রুবক অক্ষর *addr = channel_fwd_bind_addr(ssh, lhost, ফাঁকা, 1, fwd_opts);

	জন্য (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		যদি (c == ফাঁকা || c->type != SSH_CHANNEL_PORT_LISTENER)
			চালু;
		যদি (c->listening_port != lport)
			চালু;
		যদি (cport == CHANNEL_CANCEL_PORT_STATIC) {
			/* skip dynamic forwardings */
			যদি (c->host_port == 0)
				চালু;
		} অন্যথা {
			যদি (c->host_port != cport)
				চালু;
		}
		যদি ((c->listening_addr == ফাঁকা && addr != ফাঁকা) ||
		    (c->listening_addr != ফাঁকা && addr == ফাঁকা))
			চালু;
		যদি (addr == ফাঁকা || strcmp(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ফেরত found;
}

স্থির পূর্ণসংখ্যা
channel_cancel_lport_listener_streamlocal(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *path)
{
	u_int i;
	পূর্ণসংখ্যা found = 0;

	যদি (path == ফাঁকা) {
		error_f("no path specified.");
		ফেরত 0;
	}

	জন্য (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		যদি (c == ফাঁকা || c->type != SSH_CHANNEL_UNIX_LISTENER)
			চালু;
		যদি (c->listening_addr == ফাঁকা)
			চালু;
		যদি (strcmp(c->listening_addr, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ফেরত found;
}

পূর্ণসংখ্যা
channel_cancel_lport_listener(কাঠামো ssh *ssh,
    কাঠামো Forward *fwd, পূর্ণসংখ্যা cport, কাঠামো ForwardOptions *fwd_opts)
{
	যদি (fwd->listen_path != ফাঁকা) {
		ফেরত channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} অন্যথা {
		ফেরত channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
পূর্ণসংখ্যা
channel_setup_local_fwd_listener(কাঠামো ssh *ssh,
    কাঠামো Forward *fwd, কাঠামো ForwardOptions *fwd_opts)
{
	যদি (fwd->listen_path != ফাঁকা) {
		ফেরত channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} অন্যথা {
		ফেরত channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_PORT_LISTENER, fwd, ফাঁকা, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
স্থির পূর্ণসংখ্যা
remote_open_match(কাঠামো permission *allowed_open, কাঠামো Forward *fwd)
{
	পূর্ণসংখ্যা ret;
	অক্ষর *lhost;

	/* XXX add ACLs for streamlocal */
	যদি (fwd->listen_path != ফাঁকা)
		ফেরত 1;

	যদি (fwd->listen_host == ফাঁকা || allowed_open->listen_host == ফাঁকা)
		ফেরত 0;

	যদি (allowed_open->listen_port != FWD_PERMIT_ANY_PORT &&
	    allowed_open->listen_port != fwd->listen_port)
		ফেরত 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = match_pattern(lhost, allowed_open->listen_host);
	মুক্ত(lhost);

	ফেরত ret;
}

/* Checks whether a requested remote forwarding is permitted */
স্থির পূর্ণসংখ্যা
check_rfwd_permission(কাঠামো ssh *ssh, কাঠামো Forward *fwd)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	কাঠামো permission_set *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	কাঠামো permission *perm;

#ifdef SKIP_PRIVDROP
	যদি (fwd->listen_path != ফাঁকা)
		ফেরত 0;
	যদি (fwd->listen_port != 0 && fwd->listen_port < 1024)
		ফেরত 0;
#endif

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	যদি (!permit) {
		জন্য (i = 0; i < pset->অঙ্ক_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			যদি (remote_open_match(perm, fwd)) {
				permit = 1;
				বিরতি;
			}
		}
	}

	যদি (pset->অঙ্ক_permitted_admin > 0) {
		permit_adm = 0;
		জন্য (i = 0; i < pset->অঙ্ক_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			যদি (remote_open_match(perm, fwd)) {
				permit_adm = 1;
				বিরতি;
			}
		}
	}

	ফেরত permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
পূর্ণসংখ্যা
channel_setup_remote_fwd_listener(কাঠামো ssh *ssh, কাঠামো Forward *fwd,
    পূর্ণসংখ্যা *allocated_listen_port, কাঠামো ForwardOptions *fwd_opts)
{
	যদি (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		যদি (fwd->listen_path != ফাঁকা)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_path);
		অন্যথা যদি(fwd->listen_host != ফাঁকা)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_host, fwd->listen_port );
		অন্যথা
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		ফেরত 0;
	}
	যদি (fwd->listen_path != ফাঁকা) {
		ফেরত channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} অন্যথা {
		ফেরত channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_port,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
স্থির ধ্রুবক অক্ষর *
channel_rfwd_bind_host(ধ্রুবক অক্ষর *listen_host)
{
	যদি (listen_host == ফাঁকা) {
		ফেরত "localhost";
	} অন্যথা যদি (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		ফেরত "";
	} অন্যথা
		ফেরত listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
পূর্ণসংখ্যা
channel_request_remote_forwarding(কাঠামো ssh *ssh, কাঠামো Forward *fwd)
{
	পূর্ণসংখ্যা r, success = 0, idx = -1;
	ধ্রুবক অক্ষর *host_to_connect, *listen_host, *listen_path;
	পূর্ণসংখ্যা port_to_connect, listen_port;

	/* Send the forward request to the remote side. */
	যদি (fwd->listen_path != ফাঁকা) {
		যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_path)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} অন্যথা {
		যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_GLOBAL_REQUEST)) != 0 ||
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
	যদি (success) {
		/* Record that connection to this host/port is permitted. */
		host_to_connect = listen_host = listen_path = ফাঁকা;
		port_to_connect = listen_port = 0;
		যদি (fwd->connect_path != ফাঁকা) {
			host_to_connect = fwd->connect_path;
			port_to_connect = PORT_STREAMLOCAL;
		} অন্যথা {
			host_to_connect = fwd->connect_host;
			port_to_connect = fwd->connect_port;
		}
		যদি (fwd->listen_path != ফাঁকা) {
			listen_path = fwd->listen_path;
			listen_port = PORT_STREAMLOCAL;
		} অন্যথা {
			listen_host = fwd->listen_host;
			listen_port = fwd->listen_port;
		}
		idx = permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_to_connect, port_to_connect,
		    listen_host, listen_path, listen_port, ফাঁকা);
	}
	ফেরত idx;
}

স্থির পূর্ণসংখ্যা
open_match(কাঠামো permission *allowed_open, ধ্রুবক অক্ষর *requestedhost,
    পূর্ণসংখ্যা requestedport)
{
	যদি (allowed_open->host_to_connect == ফাঁকা)
		ফেরত 0;
	যদি (allowed_open->port_to_connect != FWD_PERMIT_ANY_PORT &&
	    allowed_open->port_to_connect != requestedport)
		ফেরত 0;
	যদি (strcmp(allowed_open->host_to_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    strcmp(allowed_open->host_to_connect, requestedhost) != 0)
		ফেরত 0;
	ফেরত 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
স্থির পূর্ণসংখ্যা
open_listen_match_tcpip(কাঠামো permission *allowed_open,
    ধ্রুবক অক্ষর *requestedhost, u_short requestedport, পূর্ণসংখ্যা translate)
{
	ধ্রুবক অক্ষর *allowed_host;

	যদি (allowed_open->host_to_connect == ফাঁকা)
		ফেরত 0;
	যদি (allowed_open->listen_port != requestedport)
		ফেরত 0;
	যদি (!translate && allowed_open->listen_host == ফাঁকা &&
	    requestedhost == ফাঁকা)
		ফেরত 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	যদি (allowed_host == ফাঁকা || requestedhost == ফাঁকা ||
	    strcmp(allowed_host, requestedhost) != 0)
		ফেরত 0;
	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
open_listen_match_streamlocal(কাঠামো permission *allowed_open,
    ধ্রুবক অক্ষর *requestedpath)
{
	যদি (allowed_open->host_to_connect == ফাঁকা)
		ফেরত 0;
	যদি (allowed_open->listen_port != PORT_STREAMLOCAL)
		ফেরত 0;
	যদি (allowed_open->listen_path == ফাঁকা ||
	    strcmp(allowed_open->listen_path, requestedpath) != 0)
		ফেরত 0;
	ফেরত 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
স্থির পূর্ণসংখ্যা
channel_request_rforward_cancel_tcpip(কাঠামো ssh *ssh,
    ধ্রুবক অক্ষর *host, u_short port)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	কাঠামো permission_set *pset = &sc->local_perms;
	পূর্ণসংখ্যা r;
	u_int i;
	কাঠামো permission *perm = ফাঁকা;

	জন্য (i = 0; i < pset->অঙ্ক_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		যদি (open_listen_match_tcpip(perm, host, port, 0))
			বিরতি;
		perm = ফাঁকা;
	}
	যদি (perm == ফাঁকা) {
		debug_f("requested forward not found");
		ফেরত -1;
	}
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, port)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	ফেরত 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
স্থির পূর্ণসংখ্যা
channel_request_rforward_cancel_streamlocal(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *path)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	কাঠামো permission_set *pset = &sc->local_perms;
	পূর্ণসংখ্যা r;
	u_int i;
	কাঠামো permission *perm = ফাঁকা;

	জন্য (i = 0; i < pset->অঙ্ক_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		যদি (open_listen_match_streamlocal(perm, path))
			বিরতি;
		perm = ফাঁকা;
	}
	যদি (perm == ফাঁকা) {
		debug_f("requested forward not found");
		ফেরত -1;
	}
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, path)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	ফেরত 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
পূর্ণসংখ্যা
channel_request_rforward_cancel(কাঠামো ssh *ssh, কাঠামো Forward *fwd)
{
	যদি (fwd->listen_path != ফাঁকা) {
		ফেরত channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_path);
	} অন্যথা {
		ফেরত channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_port ? fwd->listen_port : fwd->allocated_port);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
শূন্য
channel_permit_all(কাঠামো ssh *ssh, পূর্ণসংখ্যা where)
{
	কাঠামো permission_set *pset = permission_set_get(ssh, where);

	যদি (pset->অঙ্ক_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
শূন্য
channel_add_permission(কাঠামো ssh *ssh, পূর্ণসংখ্যা who, পূর্ণসংখ্যা where,
    অক্ষর *host, পূর্ণসংখ্যা port)
{
	পূর্ণসংখ্যা local = where == FORWARD_LOCAL;
	কাঠামো permission_set *pset = permission_set_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, port);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_set_add(ssh, who, where,
	    local ? host : ফাঁকা, local ? port : 0,
	    local ? ফাঁকা : host, ফাঁকা, local ? 0 : port, ফাঁকা);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
শূন্য
channel_disable_admin(কাঠামো ssh *ssh, পূর্ণসংখ্যা where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_set_add(ssh, FORWARD_ADM, where,
	    ফাঁকা, 0, ফাঁকা, ফাঁকা, 0, ফাঁকা);
}

/*
 * Clear a list of permitted opens.
 */
শূন্য
channel_clear_permission(কাঠামো ssh *ssh, পূর্ণসংখ্যা who, পূর্ণসংখ্যা where)
{
	কাঠামো permission **permp;
	u_int i, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);
	জন্য (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	মুক্ত(*permp);
	*permp = ফাঁকা;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
শূন্য
channel_update_permission(কাঠামো ssh *ssh, পূর্ণসংখ্যা idx, পূর্ণসংখ্যা newport)
{
	কাঠামো permission_set *pset = &ssh->chanctxt->local_perms;

	যদি (idx < 0 || (u_int)idx >= pset->অঙ্ক_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->অঙ্ক_permitted_user);
		ফেরত;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_to_connect,
	    pset->permitted_user[idx].port_to_connect);
	যদি (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	অন্যথা {
		pset->permitted_user[idx].listen_port =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
স্থির পূর্ণসংখ্যা
connect_পরবর্তী(কাঠামো ssh *ssh, কাঠামো channel_connect *cctx)
{
	পূর্ণসংখ্যা sock, sock_is_network, saved_errno;
	কাঠামো sockaddr_un *sunaddr;
	অক্ষর ntop[NI_MAXHOST];
	অক্ষর strport[MAXIMUM(NI_MAXSERV, আকার(sunaddr->sun_path))];

	জন্য (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_network = 0;
		নির্বাচন (cctx->ai->ai_family) {
		ক্ষেত্র AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (কাঠামো sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", আকার(ntop));
			strlcpy(strport, sunaddr->sun_path, আকার(strport));
			বিরতি;
		ক্ষেত্র AF_INET:
		ক্ষেত্র AF_INET6:
			যদি (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, আকার(ntop), strport, আকার(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				চালু;
			}
			sock_is_network = 1;
			বিরতি;
		পূর্বনির্ধারিত:
			চালু;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		যদি ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			যদি (cctx->ai->ai_next == ফাঁকা)
				error("socket: %.100s", strerror(errno));
			অন্যথা
				verbose("socket: %.100s", strerror(errno));
			চালু;
		}
		যদি (set_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		যদি (sock_is_network && ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(sock); /* logs errors */
		যদি (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			চালু;	/* fail -- try next */
		}
		যদি (cctx->ai->ai_family != AF_UNIX)
			set_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		ফেরত sock;
	}
	ফেরত -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
স্থির পূর্ণসংখ্যা
connect_to_helper(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *name, পূর্ণসংখ্যা port, পূর্ণসংখ্যা socktype,
    অক্ষর *ctype, অক্ষর *rname, কাঠামো channel_connect *cctx,
    পূর্ণসংখ্যা *reason, ধ্রুবক অক্ষর **errmsg)
{
	কাঠামো addrinfo hints;
	পূর্ণসংখ্যা gaierr;
	পূর্ণসংখ্যা sock = -1;
	অক্ষর strport[NI_MAXSERV];

	যদি (port == PORT_STREAMLOCAL) {
		কাঠামো sockaddr_un *sunaddr;
		কাঠামো addrinfo *ai;

		যদি (strlen(name) > আকার(sunaddr->sun_path)) {
			error("%.100s: %.100s", name, strerror(ENAMETOOLONG));
			ফেরত -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, আকার(*ai) + আকার(*sunaddr));
		ai->ai_addr = (কাঠামো sockaddr *)(ai + 1);
		ai->ai_addrlen = আকার(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (কাঠামো sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_path, name, আকার(sunaddr->sun_path));
		cctx->aitop = ai;
	} অন্যথা {
		memset(&hints, 0, আকার(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, আকার strport, "%d", port);
		যদি ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			যদি (errmsg != ফাঁকা)
				*errmsg = ssh_gai_strerror(gaierr);
			যদি (reason != ফাঁকা)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			ফেরত -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->port = port;
	cctx->ai = cctx->aitop;

	যদি ((sock = connect_পরবর্তী(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, port, strerror(errno));
		ফেরত -1;
	}

	ফেরত sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
স্থির Channel *
connect_to(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *host, পূর্ণসংখ্যা port,
    অক্ষর *ctype, অক্ষর *rname)
{
	কাঠামো channel_connect cctx;
	Channel *c;
	পূর্ণসংখ্যা sock;

	memset(&cctx, 0, আকার(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, ফাঁকা, ফাঁকা);
	যদি (sock == -1) {
		free_connect_ctx(&cctx);
		ফেরত ফাঁকা;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(আকার(cctx));
	memcpy(c->connect_ctx, &cctx, আকার(cctx));

	ফেরত c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_address(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *listen_host,
    u_short listen_port, অক্ষর *ctype, অক্ষর *rname)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	কাঠামো permission_set *pset = &sc->local_perms;
	u_int i;
	কাঠামো permission *perm;

	জন্য (i = 0; i < pset->অঙ্ক_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		যদি (open_listen_match_tcpip(perm,
		    listen_host, listen_port, 1)) {
			যদি (perm->downstream)
				ফেরত perm->downstream;
			যদি (perm->port_to_connect == 0)
				ফেরত rdynamic_connect_prepare(ssh,
				    ctype, rname);
			ফেরত connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_port);
	ফেরত ফাঁকা;
}

Channel *
channel_connect_by_listen_path(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *path,
    অক্ষর *ctype, অক্ষর *rname)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	কাঠামো permission_set *pset = &sc->local_perms;
	u_int i;
	কাঠামো permission *perm;

	জন্য (i = 0; i < pset->অঙ্ক_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		যদি (open_listen_match_streamlocal(perm, path)) {
			ফেরত connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    path);
	ফেরত ফাঁকা;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_to_port(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *host, u_short port,
    অক্ষর *ctype, অক্ষর *rname, পূর্ণসংখ্যা *reason, ধ্রুবক অক্ষর **errmsg)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	কাঠামো permission_set *pset = &sc->local_perms;
	কাঠামো channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	পূর্ণসংখ্যা sock;
	কাঠামো permission *perm;

	permit = pset->all_permitted;
	যদি (!permit) {
		জন্য (i = 0; i < pset->অঙ্ক_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			যদি (open_match(perm, host, port)) {
				permit = 1;
				বিরতি;
			}
		}
	}

	যদি (pset->অঙ্ক_permitted_admin > 0) {
		permit_adm = 0;
		জন্য (i = 0; i < pset->অঙ্ক_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			যদি (open_match(perm, host, port)) {
				permit_adm = 1;
				বিরতি;
			}
		}
	}

	যদি (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), host, port);
		যদি (reason != ফাঁকা)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		ফেরত ফাঁকা;
	}

	memset(&cctx, 0, আকার(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	যদি (sock == -1) {
		free_connect_ctx(&cctx);
		ফেরত ফাঁকা;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(আকার(cctx));
	memcpy(c->connect_ctx, &cctx, আকার(cctx));

	ফেরত c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_to_path(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *path,
    অক্ষর *ctype, অক্ষর *rname)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	কাঠামো permission_set *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	কাঠামো permission *perm;

	permit = pset->all_permitted;
	যদি (!permit) {
		জন্য (i = 0; i < pset->অঙ্ক_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			যদি (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit = 1;
				বিরতি;
			}
		}
	}

	যদি (pset->অঙ্ক_permitted_admin > 0) {
		permit_adm = 0;
		জন্য (i = 0; i < pset->অঙ্ক_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			যদি (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit_adm = 1;
				বিরতি;
			}
		}
	}

	যদি (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", path);
		ফেরত ফাঁকা;
	}
	ফেরত connect_to(ssh, path, PORT_STREAMLOCAL, ctype, rname);
}

শূন্য
channel_send_window_changes(কাঠামো ssh *ssh)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	কাঠামো winsize ws;
	পূর্ণসংখ্যা r;
	u_int i;

	জন্য (i = 0; i < sc->channels_alloc; i++) {
		যদি (sc->channels[i] == ফাঁকা || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			চালু;
		যদি (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			চালু;
		channel_request_start(ssh, i, "window-change", 0);
		যদি ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
স্থির Channel *
rdynamic_connect_prepare(কাঠামো ssh *ssh, অক্ষর *ctype, অক্ষর *rname)
{
	Channel *c;
	পূর্ণসংখ্যা r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = 0;
	c->path = ফাঁকা;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	ফেরত c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
স্থির পূর্ণসংখ্যা
rdynamic_connect_finish(কাঠামো ssh *ssh, Channel *c)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	কাঠামো permission_set *pset = &sc->local_perms;
	কাঠামো permission *perm;
	কাঠামো channel_connect cctx;
	u_int i, permit_adm = 1;
	পূর্ণসংখ্যা sock;

	যদি (pset->অঙ্ক_permitted_admin > 0) {
		permit_adm = 0;
		জন্য (i = 0; i < pset->অঙ্ক_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			যদি (open_match(perm, c->path, c->host_port)) {
				permit_adm = 1;
				বিরতি;
			}
		}
	}
	যদি (!permit_adm) {
		debug_f("requested forward not permitted");
		ফেরত -1;
	}

	memset(&cctx, 0, আকার(cctx));
	sock = connect_to_helper(ssh, c->path, c->host_port, SOCK_STREAM, ফাঁকা,
	    ফাঁকা, &cctx, ফাঁকা, ফাঁকা);
	যদি (sock == -1)
		free_connect_ctx(&cctx);
	অন্যথা {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_FINISH;
		c->connect_ctx = xmalloc(আকার(cctx));
		memcpy(c->connect_ctx, &cctx, আকার(cctx));
		channel_register_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	ফেরত sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
পূর্ণসংখ্যা
x11_create_display_inet(কাঠামো ssh *ssh, পূর্ণসংখ্যা x11_display_offset,
    পূর্ণসংখ্যা x11_use_localhost, পূর্ণসংখ্যা single_connection,
    u_int *display_numberp, পূর্ণসংখ্যা **chanids)
{
	Channel *nc = ফাঁকা;
	পূর্ণসংখ্যা display_সংখ্যা, sock, port;
	কাঠামো addrinfo hints, *ai, *aitop;
	অক্ষর strport[NI_MAXSERV];
	পূর্ণসংখ্যা gaierr, n, অঙ্ক_socks = 0, socks[অঙ্ক_SOCKS];

	যদি (chanids == ফাঁকা || x11_display_offset < 0 ||
	    x11_display_offset > UINT16_MAX - X11_BASE_PORT - MAX_DISPLAYS)
		ফেরত -1;

	জন্য (display_সংখ্যা = x11_display_offset;
	    display_সংখ্যা < x11_display_offset + MAX_DISPLAYS;
	    display_সংখ্যা++) {
		port = X11_BASE_PORT + display_সংখ্যা;
		memset(&hints, 0, আকার(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, আকার strport, "%d", port);
		যদি ((gaierr = getaddrinfo(ফাঁকা, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			ফেরত -1;
		}
		জন্য (ai = aitop; ai; ai = ai->ai_next) {
			যদি (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				চালু;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			যদি (sock == -1) {
				যদি ((errno != EINVAL) && (errno != EAFNOSUPPORT)
#ifdef EPFNOSUPPORT
				    && (errno != EPFNOSUPPORT)
#endif 
				    ) {
					error("socket: %.100s", strerror(errno));
					freeaddrinfo(aitop);
					ফেরত -1;
				} অন্যথা {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					চালু;
				}
			}
			যদি (ai->ai_family == AF_INET6)
				sock_set_v6only(sock);
			যদি (x11_use_localhost)
				set_reuseaddr(sock);
			যদি (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", port,
				    strerror(errno));
				close(sock);
				জন্য (n = 0; n < অঙ্ক_socks; n++)
					close(socks[n]);
				অঙ্ক_socks = 0;
				বিরতি;
			}
			socks[অঙ্ক_socks++] = sock;
			যদি (অঙ্ক_socks == অঙ্ক_SOCKS)
				বিরতি;
		}
		freeaddrinfo(aitop);
		যদি (অঙ্ক_socks > 0)
			বিরতি;
	}
	যদি (display_সংখ্যা >= x11_display_offset + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		ফেরত -1;
	}
	/* Start listening for connections on the socket. */
	জন্য (n = 0; n < অঙ্ক_socks; n++) {
		sock = socks[n];
		যদি (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			ফেরত -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(অঙ্ক_socks + 1, আকার(**chanids));
	জন্য (n = 0; n < অঙ্ক_socks; n++) {
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
	*display_numberp = display_সংখ্যা;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
connect_local_xsocket_path(ধ্রুবক অক্ষর *pathname)
{
	পূর্ণসংখ্যা sock;
	কাঠামো sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	যদি (sock == -1) {
		error("socket: %.100s", strerror(errno));
		ফেরত -1;
	}
	memset(&addr, 0, আকার(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, pathname, আকার addr.sun_path);
	যদি (connect(sock, (কাঠামো sockaddr *)&addr, আকার(addr)) == 0)
		ফেরত sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_path, strerror(errno));
	ফেরত -1;
}

স্থির পূর্ণসংখ্যা
connect_local_xsocket(u_int dnr)
{
	অক্ষর buf[1024];
	snprintf(buf, আকার buf, _PATH_UNIX_X, dnr);
	ফেরত connect_local_xsocket_path(buf);
}

#ifdef __APPLE__
স্থির পূর্ণসংখ্যা
is_path_to_xsocket(ধ্রুবক অক্ষর *display, অক্ষর *path, আকার_t pathlen)
{
	কাঠামো stat sbuf;

	যদি (strlcpy(path, display, pathlen) >= pathlen) {
		error_f("display path too long");
		ফেরত 0;
	}
	যদি (display[0] != '/')
		ফেরত 0;
	যদি (stat(path, &sbuf) == 0) {
		ফেরত 1;
	} অন্যথা {
		অক্ষর *dot = strrchr(path, '.');
		যদি (dot != ফাঁকা) {
			*dot = '\0';
			যদি (stat(path, &sbuf) == 0) {
				ফেরত 1;
			}
		}
	}
	ফেরত 0;
}
#endif

পূর্ণসংখ্যা
x11_connect_display(কাঠামো ssh *ssh)
{
	u_int display_সংখ্যা;
	ধ্রুবক অক্ষর *display;
	অক্ষর buf[1024], *cp;
	কাঠামো addrinfo hints, *ai, *aitop;
	অক্ষর strport[NI_MAXSERV];
	পূর্ণসংখ্যা gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	যদি (!display) {
		error("DISPLAY not set.");
		ফেরত -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#ifdef __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		অক্ষর path[PATH_MAX];

		যদি (is_path_to_xsocket(display, path, আকার(path))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_path(path);
			যদি (sock < 0)
				ফেরত -1;

			/* OK, we now have a connection to the display. */
			ফেরত sock;
		}
	}
#endif
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	যদি (strncmp(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		যদি (sscanf(strrchr(display, ':') + 1, "%u",
		    &display_সংখ্যা) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			ফেরত -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_সংখ্যা);
		যদি (sock < 0)
			ফেরত -1;

		/* OK, we now have a connection to the display. */
		ফেরত sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, আকার(buf));
	cp = strchr(buf, ':');
	যদি (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		ফেরত -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	যদি (sscanf(cp + 1, "%u", &display_সংখ্যা) != 1 ||
	    display_সংখ্যা > UINT16_MAX - X11_BASE_PORT) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		ফেরত -1;
	}

	/* Look up the host address */
	memset(&hints, 0, আকার(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, আকার strport, "%u", X11_BASE_PORT + display_সংখ্যা);
	যদি ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		ফেরত -1;
	}
	জন্য (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		যদি (sock == -1) {
			debug2("socket: %.100s", strerror(errno));
			চালু;
		}
		/* Connect it to the display. */
		যদি (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_BASE_PORT + display_সংখ্যা, strerror(errno));
			close(sock);
			চালু;
		}
		/* Success */
		বিরতি;
	}
	freeaddrinfo(aitop);
	যদি (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_BASE_PORT + display_সংখ্যা, strerror(errno));
		ফেরত -1;
	}
	set_nodelay(sock);
	ফেরত sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
শূন্য
x11_request_forwarding_with_spoofing(কাঠামো ssh *ssh, পূর্ণসংখ্যা client_session_id,
    ধ্রুবক অক্ষর *disp, ধ্রুবক অক্ষর *proto, ধ্রুবক অক্ষর *তথ্য, পূর্ণসংখ্যা want_reply)
{
	কাঠামো ssh_channels *sc = ssh->chanctxt;
	u_int তথ্য_len = (u_int) strlen(তথ্য) / 2;
	u_int i, মান;
	ধ্রুবক অক্ষর *cp;
	অক্ষর *new_তথ্য;
	পূর্ণসংখ্যা r, screen_সংখ্যা;

	যদি (sc->x11_saved_display == ফাঁকা)
		sc->x11_saved_display = xstrdup(disp);
	অন্যথা যদি (strcmp(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		ফেরত;
	}

	cp = strchr(disp, ':');
	যদি (cp)
		cp = strchr(cp, '.');
	যদি (cp)
		screen_সংখ্যা = (u_int)strtonum(cp + 1, 0, 400, ফাঁকা);
	অন্যথা
		screen_সংখ্যা = 0;

	যদি (sc->x11_saved_proto == ফাঁকা) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_তথ্য = xmalloc(তথ্য_len);
		জন্য (i = 0; i < তথ্য_len; i++) {
			যদি (sscanf(তথ্য + 2 * i, "%2x", &মান) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", তথ্য);
			}
			sc->x11_saved_তথ্য[i] = মান;
		}
		sc->x11_saved_তথ্য_len = তথ্য_len;

		/* Generate fake data of the same length. */
		sc->x11_fake_তথ্য = xmalloc(তথ্য_len);
		arc4random_buf(sc->x11_fake_তথ্য, তথ্য_len);
		sc->x11_fake_তথ্য_len = তথ্য_len;
	}

	/* Convert the fake data into hex. */
	new_তথ্য = tohex(sc->x11_fake_তথ্য, তথ্য_len);

	/* Send the request packet. */
	channel_request_start(ssh, client_session_id, "x11-req", want_reply);
	যদি ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_তথ্য)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_সংখ্যা)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	মুক্ত(new_তথ্য);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
পূর্ণসংখ্যা
x11_channel_used_recently(কাঠামো ssh *ssh) {
	u_int i;
	Channel *c;
	দ্বিগুণ lastused = 0;

	জন্য (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		যদি (c == ফাঁকা || c->ctype == ফাঁকা || c->lastused == 0.0 ||
		    strcmp(c->ctype, "x11-connection") != 0)
			চালু;
		যদি (c->lastused > lastused)
			lastused = c->lastused;
	}
	ফেরত lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
