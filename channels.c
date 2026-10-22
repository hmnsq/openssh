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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "packet.h"
#include "log.h"
#include "misc.h"
#include "channels.h"
#include "compat.h"
#include "canohost.h"
#include "pathnames.h"
#include "match.h"

/* XXX remove once we're satisfied there's no lurking bugs */
/* #define DEBUG_CHANNEL_POLL 1 */

/* -- agent forwarding */
#define	NUM_SOCKS	10

/* -- X11 forwarding */
/* X11 port for display :0 */
#define X11_BASE_PORT	6000
/* Maximum number of fake X11 displays to try. */
#define MAX_DISPLAYS  1000

/* Per-channel callback for pre/post IO actions */
typedef void chan_fn(sa_nracanaa ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
sa_nracanaa permission {
	var_na *host_to_connect;		/* Connect to 'host'. */
	පූර්ණ_සංඛ්‍යා port_to_connect;		/* Connect to 'port'. */
	var_na *listen_host;		/* Remote side should listen address. */
	var_na *listen_path;		/* Remote side should listen path. */
	පූර්ණ_සංඛ්‍යා listen_port;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
sa_nracanaa channel_connect {
	var_na *host;
	පූර්ණ_සංඛ්‍යා port;
	sa_nracanaa addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
sa_nracanaa permission_set {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int num_permitted_user;
	sa_nracanaa permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int num_permitted_admin;
	sa_nracanaa permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	පූර්ණ_සංඛ්‍යා all_permitted;
};

/* Used to record timeouts per channel type */
sa_nracanaa ssh_channel_timeout {
	var_na *type_pattern;
	dviguu_na timeout_secs;
};

/* Master structure for channels state */
sa_nracanaa ssh_channels {
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
	sa_nracanaa permission_set local_perms;
	sa_nracanaa permission_set remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	var_na *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	var_na *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	var_na *x11_saved_data;
	u_int x11_saved_data_len;

	/* Deadline after which all X11 connections are refused */
	dviguu_na x11_refuse_time;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_data;
	u_int x11_fake_data_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	පූර්ණ_සංඛ්‍යා IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	පූර්ණ_සංඛ්‍යා want_tcp_keepalive;

	/* Channel timeouts by type */
	sa_nracanaa ssh_channel_timeout *timeouts;
	size_t ntimeouts;
	/* Global timeout for all OPEN channels */
	dviguu_na global_deadline;
	dviguu_na lastused;
	/* pattern-lists used to classify channels as bulk */
	var_na *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
static void port_open_helper(sa_nracanaa ssh *ssh, Channel *c, var_na *rtype);
static const var_na *channel_rfwd_bind_host(const var_na *listen_host);

/* non-blocking connect helpers */
static පූර්ණ_සංඛ්‍යා connect_next(sa_nracanaa ssh *, sa_nracanaa channel_connect *);
static Channel *rdynamic_connect_prepare(sa_nracanaa ssh *, var_na *, var_na *);
static පූර්ණ_සංඛ්‍යා rdynamic_connect_finish(sa_nracanaa ssh *, Channel *);

/* Setup helper */
static void channel_handler_init(sa_nracanaa ssh_channels *sc);

/* -- channel core */

void
channel_init_channels(sa_nracanaa ssh *ssh)
{
	sa_nracanaa ssh_channels *sc;

	නම් ((sc = calloc(1, parimaa_na(*sc))) == NULL)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, parimaa_na(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා id)
{
	Channel *c;

	නම් (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		ආපසු NULL;
	}
	c = ssh->chanctxt->channels[id];
	නම් (c == NULL) {
		logit_f("%d: bad id: channel free", id);
		ආපසු NULL;
	}
	ආපසු c;
}

Channel *
channel_by_remote_id(sa_nracanaa ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	සඳහා (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		නම් (c != NULL && c->have_remote_id && c->remote_id == remote_id)
			ආපසු c;
	}
	ආපසු NULL;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා id)
{
	Channel *c;

	නම් ((c = channel_by_id(ssh, id)) == NULL)
		ආපසු NULL;

	switch (c->type) {
	pak_sa SSH_CHANNEL_X11_OPEN:
	pak_sa SSH_CHANNEL_LARVAL:
	pak_sa SSH_CHANNEL_CONNECTING:
	pak_sa SSH_CHANNEL_DYNAMIC:
	pak_sa SSH_CHANNEL_RDYNAMIC_OPEN:
	pak_sa SSH_CHANNEL_RDYNAMIC_FINISH:
	pak_sa SSH_CHANNEL_OPENING:
	pak_sa SSH_CHANNEL_OPEN:
	pak_sa SSH_CHANNEL_ABANDONED:
	pak_sa SSH_CHANNEL_MUX_PROXY:
		ආපසු c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	ආපසු NULL;
}

static void
free_connect_ctx(sa_nracanaa channel_connect *cctx)
{
	free(cctx->host);
	නම් (cctx->aitop) {
		නම් (cctx->aitop->ai_family == AF_UNIX)
			free(cctx->aitop);
		නැතහොත්
			freeaddrinfo(cctx->aitop);
	}
	memset(cctx, 0, parimaa_na(*cctx));
}

static void
channel_free_connect_ctx(Channel *c)
{
	නම් (c == NULL || c->connect_ctx == NULL)
		ආපසු;
	free_connect_ctx(c->connect_ctx);
	free(c->connect_ctx);
	c->connect_ctx = NULL;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
void
channel_set_tcp_keepalives(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
void
channel_add_timeout(sa_nracanaa ssh *ssh, const var_na *type_pattern,
    dviguu_na timeout_secs)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;

	නම් (strcmp(type_pattern, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		ආපසු;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_pattern, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, parimaa_na(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_pattern = xstrdup(type_pattern);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
void
channel_clear_timeouts(sa_nracanaa ssh *ssh)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	size_t i;

	debug3_f("clearing");
	සඳහා (i = 0; i < sc->ntimeouts; i++)
		free(sc->timeouts[i].type_pattern);
	free(sc->timeouts);
	sc->timeouts = NULL;
	sc->ntimeouts = 0;
}

static dviguu_na
lookup_timeout(sa_nracanaa ssh *ssh, const var_na *type)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	size_t i;

	සඳහා (i = 0; i < sc->ntimeouts; i++) {
		නම් (match_pattern(type, sc->timeouts[i].type_pattern))
			ආපසු sc->timeouts[i].timeout_secs;
	}

	ආපසු 0;
}

static void
channel_classify(sa_nracanaa ssh *ssh, Channel *c)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	const var_na *type = c->xctype == NULL ? c->ctype : c->xctype;
	const පූර්ණ_සංඛ්‍යා has_tty = c->isatty || c->remote_has_tty;
	const var_na *classifier = has_tty ?
	    sc->bulk_classifier_tty : sc->bulk_classifier_notty;

	c->bulk = type != NULL && match_pattern_list(type, classifier, 0) == 1;
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
void
channel_set_xtype(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා id, const var_na *xctype)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	නම් ((c = channel_by_id(ssh, id)) == NULL)
		fatal_f("missing channel %d", id);
	නම් (c->xctype != NULL)
		free(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	dviguu_na xtype_deadline = lookup_timeout(ssh, c->xctype);
	නම් (xtype_deadline != 0)
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
static void
channel_set_used_time(sa_nracanaa ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	නම් (c != NULL)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
static dviguu_na
channel_get_expiry(sa_nracanaa ssh *ssh, Channel *c)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	dviguu_na expiry = 0, channel_expiry;

	නම් (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	නම් (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		නම් (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	ආපසු expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
පූර්ණ_සංඛ්‍යා
channel_has_bulk(sa_nracanaa ssh *ssh)
{
	ආපසු ssh->chanctxt != NULL && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
static void
channel_register_fds(sa_nracanaa ssh *ssh, Channel *c, පූර්ණ_සංඛ්‍යා rfd, පූර්ණ_සංඛ්‍යා wfd, පූර්ණ_සංඛ්‍යා efd,
    පූර්ණ_සංඛ්‍යා extusage, පූර්ණ_සංඛ්‍යා nonblock, පූර්ණ_සංඛ්‍යා is_tty)
{
	පූර්ණ_සංඛ්‍යා val;

	නම් (rfd != -1)
		(void)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	නම් (wfd != -1 && wfd != rfd)
		(void)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	නම් (efd != -1 && efd != rfd && efd != wfd)
		(void)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	නම් ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#endif

	/* enable nonblocking mode */
	c->restore_block = 0;
	නම් (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		නම් (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_block |= CHANNEL_RESTORE_RFD;
			set_nonblock(rfd);
		}
		නම් (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_block |= CHANNEL_RESTORE_WFD;
			set_nonblock(wfd);
		}
		නම් (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_block |= CHANNEL_RESTORE_EFD;
			set_nonblock(efd);
		}
	} නැතහොත් නම් (nonblock) {
		නම් (rfd != -1)
			set_nonblock(rfd);
		නම් (wfd != -1)
			set_nonblock(wfd);
		නම් (efd != -1)
			set_nonblock(efd);
	}
	/* channel might be entering a larval state, so reset global timeout */
	channel_set_used_time(ssh, NULL);
	channel_classify(ssh, c);
}

/*
 * Allocate a new channel object and set its type and socket.
 */
Channel *
channel_new(sa_nracanaa ssh *ssh, var_na *ctype, පූර්ණ_සංඛ්‍යා type, පූර්ණ_සංඛ්‍යා rfd, පූර්ණ_සංඛ්‍යා wfd, පූර්ණ_සංඛ්‍යා efd,
    u_int window, u_int maxpack, පූර්ණ_සංඛ්‍යා extusage, const var_na *remote_name,
    පූර්ණ_සංඛ්‍යා nonblock)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	u_int i, found = 0;
	Channel *c;
	පූර්ණ_සංඛ්‍යා r;

	/* Try to find a free slot where to put the new channel. */
	සඳහා (i = 0; i < sc->channels_alloc; i++) {
		නම් (sc->channels[i] == NULL) {
			/* Found a free slot. */
			found = i;
			bha_nga;
		}
	}
	නම් (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		found = sc->channels_alloc;
		නම් (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, parimaa_na(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[found] = xcalloc(1, parimaa_na(Channel));
	නම් ((c->input = sshbuf_new()) == NULL ||
	    (c->output = sshbuf_new()) == NULL ||
	    (c->extended = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	නම් ((r = sshbuf_set_max_size(c->input, CHAN_INPUT_MAX)) != 0)
		fatal_fr(r, "sshbuf_set_max_size");
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_INPUT_OPEN;
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
	ආපසු c;
}

void
channel_set_tty(sa_nracanaa ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

පූර්ණ_සංඛ්‍යා
channel_close_fd(sa_nracanaa ssh *ssh, Channel *c, පූර්ණ_සංඛ්‍යා *fdp)
{
	පූර්ණ_සංඛ්‍යා ret, fd = *fdp;

	නම් (fd == -1)
		ආපසු 0;

	/* restore blocking */
	නම් (*fdp == c->rfd &&
	    (c->restore_block & CHANNEL_RESTORE_RFD) != 0)
		(void)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	නැතහොත් නම් (*fdp == c->wfd &&
	    (c->restore_block & CHANNEL_RESTORE_WFD) != 0)
		(void)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	නැතහොත් නම් (*fdp == c->efd &&
	    (c->restore_block & CHANNEL_RESTORE_EFD) != 0)
		(void)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	නම් (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	නම් (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	නම් (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	නම් (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = close(fd);
	*fdp = -1; /* probably redundant */
	ආපසු ret;
}

/* Close all channel fd/socket. */
static void
channel_close_fds(sa_nracanaa ssh *ssh, Channel *c)
{
	පූර්ණ_සංඛ්‍යා sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	නම් (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	නම් (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	නම් (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

static void
fwd_perm_clear(sa_nracanaa permission *perm)
{
	free(perm->host_to_connect);
	free(perm->listen_host);
	free(perm->listen_path);
	memset(perm, 0, parimaa_na(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
static const var_na *
fwd_ident(පූර්ණ_සංඛ්‍යා who, පූර්ණ_සංඛ්‍යා where)
{
	නම් (who == FORWARD_ADM) {
		නම් (where == FORWARD_LOCAL)
			ආපසු "admin local";
		නැතහොත් නම් (where == FORWARD_REMOTE)
			ආපසු "admin remote";
	} නැතහොත් නම් (who == FORWARD_USER) {
		නම් (where == FORWARD_LOCAL)
			ආපසු "user local";
		නැතහොත් නම් (where == FORWARD_REMOTE)
			ආපසු "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
static sa_nracanaa permission_set *
permission_set_get(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා where)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;

	switch (where) {
	pak_sa FORWARD_LOCAL:
		ආපසු &sc->local_perms;
		bha_nga;
	pak_sa FORWARD_REMOTE:
		ආපසු &sc->remote_perms;
		bha_nga;
	default:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
static void
permission_set_get_array(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා who, පූර්ණ_සංඛ්‍යා where,
    sa_nracanaa permission ***permpp, u_int **npermpp)
{
	sa_nracanaa permission_set *pset = permission_set_get(ssh, where);

	switch (who) {
	pak_sa FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->num_permitted_user;
		bha_nga;
	pak_sa FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->num_permitted_admin;
		bha_nga;
	default:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
static පූර්ණ_සංඛ්‍යා
permission_set_add(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා who, පූර්ණ_සංඛ්‍යා where,
    const var_na *host_to_connect, පූර්ණ_සංඛ්‍යා port_to_connect,
    const var_na *listen_host, const var_na *listen_path, පූර්ණ_සංඛ්‍යා listen_port,
    Channel *downstream)
{
	sa_nracanaa permission **permp;
	u_int n, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);

	නම් (*npermp >= INT_MAX)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, parimaa_na(**permp));
	n = (*npermp)++;
#define MAYBE_DUP(s) ((s == NULL) ? NULL : xstrdup(s))
	(*permp)[n].host_to_connect = MAYBE_DUP(host_to_connect);
	(*permp)[n].port_to_connect = port_to_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_path = MAYBE_DUP(listen_path);
	(*permp)[n].listen_port = listen_port;
	(*permp)[n].downstream = downstream;
#undef MAYBE_DUP
	ආපසු (පූර්ණ_සංඛ්‍යා)n;
}

static void
mux_remove_remote_forwardings(sa_nracanaa ssh *ssh, Channel *c)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	sa_nracanaa permission_set *pset = &sc->local_perms;
	sa_nracanaa permission *perm;
	පූර්ණ_සංඛ්‍යා r;
	u_int i;

	සඳහා (i = 0; i < pset->num_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		නම් (perm->downstream != c)
			continue;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_port);
		නම් ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
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
void
channel_free(sa_nracanaa ssh *ssh, Channel *c)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	var_na *s;
	u_int i, n;
	Channel *other;
	sa_nracanaa channel_confirm *cc;

	සඳහා (n = 0, i = 0; i < sc->channels_alloc; i++) {
		නම් ((other = sc->channels[i]) == NULL)
			continue;
		n++;
		/* detach from mux client and prepare for closing */
		නම් (c->type == SSH_CHANNEL_MUX_CLIENT &&
		    other->type == SSH_CHANNEL_MUX_PROXY &&
		    other->mux_ctx == c) {
			other->mux_ctx = NULL;
			other->type = SSH_CHANNEL_OPEN;
			other->istate = CHAN_INPUT_CLOSED;
			other->ostate = CHAN_OUTPUT_CLOSED;
		}
	}
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	නම් (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		free(c->mux_ctx);
		c->mux_ctx = NULL;
	} නැතහොත් නම් (c->type == SSH_CHANNEL_MUX_LISTENER) {
		free(c->mux_ctx);
		c->mux_ctx = NULL;
	}

	නම් (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
		s = channel_open_message(ssh);
		debug3("channel %d: status: %s", c->self, s);
		free(s);
	}

	channel_close_fds(ssh, c);
	sshbuf_free(c->input);
	sshbuf_free(c->output);
	sshbuf_free(c->extended);
	c->input = c->output = c->extended = NULL;
	free(c->remote_name);
	c->remote_name = NULL;
	free(c->path);
	c->path = NULL;
	free(c->listening_addr);
	c->listening_addr = NULL;
	free(c->xctype);
	c->xctype = NULL;
	channel_free_connect_ctx(c);
	අතරතුර ((cc = TAILQ_FIRST(&c->status_confirms)) != NULL) {
		නම් (cc->abandon_cb != NULL)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->status_confirms, cc, entry);
		freezero(cc, parimaa_na(*cc));
	}
	නම් (c->filter_cleanup != NULL && c->filter_ctx != NULL)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = NULL;
	freezero(c, parimaa_na(*c));
}

void
channel_free_all(sa_nracanaa ssh *ssh)
{
	u_int i;
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;

	සඳහා (i = 0; i < sc->channels_alloc; i++)
		නම් (sc->channels[i] != NULL)
			channel_free(ssh, sc->channels[i]);

	free(sc->channels);
	sc->channels = NULL;
	sc->channels_alloc = 0;

	free(sc->x11_saved_display);
	sc->x11_saved_display = NULL;

	free(sc->x11_saved_proto);
	sc->x11_saved_proto = NULL;

	free(sc->x11_saved_data);
	sc->x11_saved_data = NULL;
	sc->x11_saved_data_len = 0;

	free(sc->x11_fake_data);
	sc->x11_fake_data = NULL;
	sc->x11_fake_data_len = 0;
}

void
channel_free_channels(sa_nracanaa ssh *ssh)
{
	sa_nracanaa ssh_channels *sc;

	නම් (ssh == NULL || ssh->chanctxt == NULL)
		ආපසු;
	channel_free_all(ssh);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_USER, FORWARD_REMOTE);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_LOCAL);
	channel_clear_permission(ssh, FORWARD_ADM, FORWARD_REMOTE);
	sc = ssh->chanctxt;
	free(sc->bulk_classifier_tty);
	free(sc->bulk_classifier_notty);
	free(sc->channel_pre);
	free(sc->channel_post);
	freezero(sc, parimaa_na(*sc));
	ssh->chanctxt = NULL;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
void
channel_close_all(sa_nracanaa ssh *ssh)
{
	u_int i;

	සඳහා (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		නම් (ssh->chanctxt->channels[i] != NULL)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
void
channel_stop_listening(sa_nracanaa ssh *ssh)
{
	u_int i;
	Channel *c;

	සඳහා (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		නම් (c != NULL) {
			switch (c->type) {
			pak_sa SSH_CHANNEL_AUTH_SOCKET:
			pak_sa SSH_CHANNEL_PORT_LISTENER:
			pak_sa SSH_CHANNEL_RPORT_LISTENER:
			pak_sa SSH_CHANNEL_X11_LISTENER:
			pak_sa SSH_CHANNEL_UNIX_LISTENER:
			pak_sa SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				bha_nga;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
පූර්ණ_සංඛ්‍යා
channel_not_very_much_buffered_data(sa_nracanaa ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	සඳහා (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		නම් (c == NULL || c->type != SSH_CHANNEL_OPEN)
			continue;
		නම් (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			ආපසු 0;
		}
	}
	ආපසු 1;
}

/* Returns true if any channel is still open. */
පූර්ණ_සංඛ්‍යා
channel_still_open(sa_nracanaa ssh *ssh)
{
	u_int i;
	Channel *c;

	සඳහා (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		නම් (c == NULL)
			continue;
		switch (c->type) {
		pak_sa SSH_CHANNEL_X11_LISTENER:
		pak_sa SSH_CHANNEL_PORT_LISTENER:
		pak_sa SSH_CHANNEL_RPORT_LISTENER:
		pak_sa SSH_CHANNEL_MUX_LISTENER:
		pak_sa SSH_CHANNEL_CLOSED:
		pak_sa SSH_CHANNEL_AUTH_SOCKET:
		pak_sa SSH_CHANNEL_DYNAMIC:
		pak_sa SSH_CHANNEL_RDYNAMIC_OPEN:
		pak_sa SSH_CHANNEL_CONNECTING:
		pak_sa SSH_CHANNEL_ZOMBIE:
		pak_sa SSH_CHANNEL_ABANDONED:
		pak_sa SSH_CHANNEL_UNIX_LISTENER:
		pak_sa SSH_CHANNEL_RUNIX_LISTENER:
			continue;
		pak_sa SSH_CHANNEL_LARVAL:
			continue;
		pak_sa SSH_CHANNEL_OPENING:
		pak_sa SSH_CHANNEL_OPEN:
		pak_sa SSH_CHANNEL_RDYNAMIC_FINISH:
		pak_sa SSH_CHANNEL_X11_OPEN:
		pak_sa SSH_CHANNEL_MUX_CLIENT:
		pak_sa SSH_CHANNEL_MUX_PROXY:
			ආපසු 1;
		default:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ආපසු 0;
}

/* Returns true if a channel with a TTY is open. */
පූර්ණ_සංඛ්‍යා
channel_tty_open(sa_nracanaa ssh *ssh)
{
	u_int i;
	Channel *c;

	සඳහා (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		නම් (c == NULL || c->type != SSH_CHANNEL_OPEN)
			continue;
		නම් (c->client_tty)
			ආපසු 1;
	}
	ආපසු 0;
}

/* Returns the id of an open channel suitable for keepaliving */
පූර්ණ_සංඛ්‍යා
channel_find_open(sa_nracanaa ssh *ssh)
{
	u_int i;
	Channel *c;

	සඳහා (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		නම් (c == NULL || !c->have_remote_id)
			continue;
		switch (c->type) {
		pak_sa SSH_CHANNEL_CLOSED:
		pak_sa SSH_CHANNEL_DYNAMIC:
		pak_sa SSH_CHANNEL_RDYNAMIC_OPEN:
		pak_sa SSH_CHANNEL_RDYNAMIC_FINISH:
		pak_sa SSH_CHANNEL_X11_LISTENER:
		pak_sa SSH_CHANNEL_PORT_LISTENER:
		pak_sa SSH_CHANNEL_RPORT_LISTENER:
		pak_sa SSH_CHANNEL_MUX_LISTENER:
		pak_sa SSH_CHANNEL_MUX_CLIENT:
		pak_sa SSH_CHANNEL_MUX_PROXY:
		pak_sa SSH_CHANNEL_OPENING:
		pak_sa SSH_CHANNEL_CONNECTING:
		pak_sa SSH_CHANNEL_ZOMBIE:
		pak_sa SSH_CHANNEL_ABANDONED:
		pak_sa SSH_CHANNEL_UNIX_LISTENER:
		pak_sa SSH_CHANNEL_RUNIX_LISTENER:
			continue;
		pak_sa SSH_CHANNEL_LARVAL:
		pak_sa SSH_CHANNEL_AUTH_SOCKET:
		pak_sa SSH_CHANNEL_OPEN:
		pak_sa SSH_CHANNEL_X11_OPEN:
			ආපසු i;
		default:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	ආපසු -1;
}

/* Returns the state of the channel's extended usage flag */
const var_na *
channel_format_extended_usage(const Channel *c)
{
	නම් (c->efd == -1)
		ආපසු "closed";

	switch (c->extended_usage) {
	pak_sa CHAN_EXTENDED_WRITE:
		ආපසු "write";
	pak_sa CHAN_EXTENDED_READ:
		ආපසු "read";
	pak_sa CHAN_EXTENDED_IGNORE:
		ආපසු "ignore";
	default:
		ආපසු "UNKNOWN";
	}
}

static var_na *
channel_format_status(const Channel *c)
{
	var_na *ret = NULL;

	xasprintf(&ret, "t%d [%s] %s%u %s%u i%u/%zu o%u/%zu e[%s]/%zu "
	    "fd %d/%d/%d sock %d cc %d %s%u io 0x%02x/0x%02x %s%s",
	    c->type, c->xctype != NULL ? c->xctype : c->ctype,
	    c->have_remote_id ? "r" : "nr", c->remote_id,
	    c->mux_ctx != NULL ? "m" : "nm", c->mux_downstream_id,
	    c->istate, sshbuf_len(c->input),
	    c->ostate, sshbuf_len(c->output),
	    channel_format_extended_usage(c), sshbuf_len(c->extended),
	    c->rfd, c->wfd, c->efd, c->sock, c->ctl_chan,
	    c->have_ctl_child_id ? "c" : "nc", c->ctl_child_id,
	    c->io_want, c->io_ready,
	    c->isatty ? "T" : (c->remote_has_tty ? "RT" : ""),
	    c->bulk ? "B" : "I");
	ආපසු ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
var_na *
channel_open_message(sa_nracanaa ssh *ssh)
{
	sa_nracanaa sshbuf *buf;
	Channel *c;
	u_int i;
	පූර්ණ_සංඛ්‍යා r;
	var_na *cp, *ret;

	නම් ((buf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	නම් ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	සඳහා (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		නම් (c == NULL)
			continue;
		switch (c->type) {
		pak_sa SSH_CHANNEL_X11_LISTENER:
		pak_sa SSH_CHANNEL_PORT_LISTENER:
		pak_sa SSH_CHANNEL_RPORT_LISTENER:
		pak_sa SSH_CHANNEL_CLOSED:
		pak_sa SSH_CHANNEL_AUTH_SOCKET:
		pak_sa SSH_CHANNEL_ZOMBIE:
		pak_sa SSH_CHANNEL_ABANDONED:
		pak_sa SSH_CHANNEL_MUX_LISTENER:
		pak_sa SSH_CHANNEL_UNIX_LISTENER:
		pak_sa SSH_CHANNEL_RUNIX_LISTENER:
			continue;
		pak_sa SSH_CHANNEL_LARVAL:
		pak_sa SSH_CHANNEL_OPENING:
		pak_sa SSH_CHANNEL_CONNECTING:
		pak_sa SSH_CHANNEL_DYNAMIC:
		pak_sa SSH_CHANNEL_RDYNAMIC_OPEN:
		pak_sa SSH_CHANNEL_RDYNAMIC_FINISH:
		pak_sa SSH_CHANNEL_OPEN:
		pak_sa SSH_CHANNEL_X11_OPEN:
		pak_sa SSH_CHANNEL_MUX_PROXY:
		pak_sa SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_status(c);
			නම් ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
			    c->self, c->remote_name, cp)) != 0) {
				free(cp);
				fatal_fr(r, "sshbuf_putf");
			}
			free(cp);
			continue;
		default:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	නම් ((ret = sshbuf_dup_string(buf)) == NULL)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	ආපසු ret;
}

void
channel_report_open(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා level)
{
	var_na *open, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, parimaa_na(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (long)getpid());
	open = oopen = channel_open_message(ssh);
	අතරතුර ((cp = strsep(&open, "\r\n")) != NULL) {
		නම් (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	free(oopen);
}

static void
open_preamble(sa_nracanaa ssh *ssh, const var_na *where, Channel *c, const var_na *type)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

void
channel_send_open(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා id)
{
	Channel *c = channel_lookup(ssh, id);
	පූර්ණ_සංඛ්‍යා r;

	නම් (c == NULL) {
		logit("channel_send_open: %d: bad id", id);
		ආපසු;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	නම් ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

void
channel_request_start(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා id, const var_na *service,
    පූර්ණ_සංඛ්‍යා wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	පූර්ණ_සංඛ්‍යා r;

	නම් (c == NULL) {
		logit_f("%d: unknown channel id", id);
		ආපසු;
	}
	නම් (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	නම් ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

void
channel_register_status_confirm(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, void *ctx)
{
	sa_nracanaa channel_confirm *cc;
	Channel *c;

	නම් ((c = channel_lookup(ssh, id)) == NULL)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, parimaa_na(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->status_confirms, cc, entry);
}

void
channel_register_open_confirm(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා id,
    channel_open_fn *fn, void *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	නම් (c == NULL) {
		logit_f("%d: bad id", id);
		ආපසු;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

void
channel_register_cleanup(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා id,
    channel_callback_fn *fn, පූර්ණ_සංඛ්‍යා do_close)
{
	Channel *c = channel_by_id(ssh, id);

	නම් (c == NULL) {
		logit_f("%d: bad id", id);
		ආපසු;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

void
channel_cancel_cleanup(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා id)
{
	Channel *c = channel_by_id(ssh, id);

	නම් (c == NULL) {
		logit_f("%d: bad id", id);
		ආපසු;
	}
	c->detach_user = NULL;
	c->detach_close = 0;
}

void
channel_register_filter(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, void *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	නම් (c == NULL) {
		logit_f("%d: bad id", id);
		ආපසු;
	}
	c->input_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

void
channel_set_fds(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා id, පූර්ණ_සංඛ්‍යා rfd, පූර්ණ_සංඛ්‍යා wfd, පූර්ණ_සංඛ්‍යා efd,
    පූර්ණ_සංඛ්‍යා extusage, පූර්ණ_සංඛ්‍යා nonblock, පූර්ණ_සංඛ්‍යා is_tty, u_int window_max)
{
	Channel *c = channel_lookup(ssh, id);
	පූර්ණ_සංඛ්‍යා r;

	නම් (c == NULL || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	නම් (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_register_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_set_used_time(ssh, c);
	c->local_window = c->local_window_max = window_max;

	නම් ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_WINDOW_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

static void
channel_pre_listener(sa_nracanaa ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

static void
channel_pre_connecting(sa_nracanaa ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

static void
channel_pre_open(sa_nracanaa ssh *ssh, Channel *c)
{
	c->io_want = 0;
	නම් (c->istate == CHAN_INPUT_OPEN &&
	    c->remote_window > 0 &&
	    sshbuf_len(c->input) < c->remote_window &&
	    sshbuf_check_reserve(c->input, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	නම් (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		නම් (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} නැතහොත් නම් (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			නම් (CHANNEL_EFD_OUTPUT_ACTIVE(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			නැතහොත්
				chan_obuf_empty(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	නම් (c->efd != -1 && !(c->istate == CHAN_INPUT_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		නම් (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		නැතහොත් නම් (c->efd != -1 && !(c->flags & CHAN_EOF_SENT) &&
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
static පූර්ණ_සංඛ්‍යා
x11_open_helper(sa_nracanaa ssh *ssh, sa_nracanaa sshbuf *b)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, data_len;

	නම් (sc->x11_saved_proto == NULL) {
		error("X11 forwarding opened before X11 forwarding requested");
		ආපසු -1;
	}

	/* Is this being called after the refusal deadline? */
	නම් (sc->x11_refuse_time != 0.0 &&
	    monotime_double() >= sc->x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		ආපසු -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	නම් (sshbuf_len(b) < 12)
		ආපසු 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	නම් (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		data_len = 256 * ucp[8] + ucp[9];
	} නැතහොත් නම් (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		data_len = ucp[8] + 256 * ucp[9];
	} නැතහොත් {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		ආපසු -1;
	}

	/* Check if the whole packet is in buffer. */
	නම් (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((data_len + 3) & ~3))
		ආපසු 0;

	/* Check if authentication protocol matches. */
	නම් (proto_len != strlen(sc->x11_saved_proto) ||
	    memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		ආපසු -1;
	}
	/* Check if authentication data matches our fake data. */
	නම් (data_len != sc->x11_fake_data_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_data, sc->x11_fake_data_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		ආපසු -1;
	}
	/* Check fake data length */
	නම් (sc->x11_fake_data_len != sc->x11_saved_data_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_data_len, sc->x11_saved_data_len);
		ආපසු -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	memcpy(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_data, sc->x11_saved_data_len);
	ආපසු 1;
}

void
channel_force_close(sa_nracanaa ssh *ssh, Channel *c, පූර්ණ_සංඛ්‍යා abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	නම් (c->istate == CHAN_INPUT_OPEN)
		chan_read_failed(ssh, c);
	නම් (c->istate == CHAN_INPUT_WAIT_DRAIN) {
		sshbuf_reset(c->input);
		chan_ibuf_empty(ssh, c);
	}
	නම් (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	නම් (c->detach_user)
		c->detach_user(ssh, c->self, 1, NULL);
	නම් (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	නම් (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

static void
channel_pre_x11_open(sa_nracanaa ssh *ssh, Channel *c)
{
	පූර්ණ_සංඛ්‍යා ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	නම් (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		channel_pre_open(ssh, c);
	} නැතහොත් නම් (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

static void
channel_pre_mux_client(sa_nracanaa ssh *ssh, Channel *c)
{
	c->io_want = 0;
	නම් (c->istate == CHAN_INPUT_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->input, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	නම් (c->istate == CHAN_INPUT_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->input);
		chan_ibuf_empty(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	නම් (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		නම් (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		නැතහොත් නම් (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_empty(ssh, c);
	}
}

static anta_hstha පූර්ණ_සංඛ්‍යා
socks_decode_error(Channel *c, පූර්ණ_සංඛ්‍යා status, const var_na *func, const var_na *msg)
{
	නම් (status == SSH_ERR_MESSAGE_INCOMPLETE)
		ආපසු 0;
	නැතහොත් {
		debug_r(status, "%s: channel %d: decode %s",
		    func, c->self, msg);
		ආපසු -1;
	}
}

/* try to decode a socks4 header */
static පූර්ණ_සංඛ්‍යා
channel_decode_socks4(Channel *c, sa_nracanaa sshbuf *input, sa_nracanaa sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_port;
	var_na *user = NULL, *host = NULL;
	පූර්ණ_සංඛ්‍යා success = -1, socks4a = 0, r;
	sa_nracanaa sshbuf *b = NULL;

	නම් (sshbuf_len(input) < 9)
		ආපසු 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	නම් ((b = sshbuf_fromb(input)) == NULL)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	නම් ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, parimaa_na(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, NULL)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		goto out;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	නම් (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		නම් ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, NULL)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			goto out;
		}
		socks4a = 1;
	} නැතහොත් {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	නම් ((r = sshbuf_consume_upto_child(input, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (පූර්ණ_සංඛ්‍යා)socks_cmd,
	    host, dest_port);
	නම් (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		goto out;
	}
	free(c->path);
	c->path = host;
	host = NULL; /* transferred */
	c->host_port = dest_port;

	/* Reply to the SOCKS4 client */
	නම් ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
	    (r = sshbuf_put_u8(output, 90)) != 0 ||	/* cd: req granted */
	    (r = sshbuf_put_u16(output, 0)) != 0 ||	/* port: ignored */
	    (r = sshbuf_put_u32(output, ntohl(INADDR_ANY))) != 0) /* ignored */
		fatal_fr(r, "channel %d: compose reply", c->self);

	/* success */
	success = 1;
 out:
	sshbuf_free(b);
	free(user);
	free(host);
	ආපසු success;
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
static පූර්ණ_සංඛ්‍යා
channel_socks5_check_auth(Channel *c, sa_nracanaa sshbuf *b, sa_nracanaa sshbuf *input,
    sa_nracanaa sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, method;
	පූර්ණ_සංඛ්‍යා r;
	u_int i, found;

	/* format: ver | nmethods | methods */
	නම් ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		ආපසු socks_decode_error(c, r, __func__, "version");
	නම් (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	නම් ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		ආපසු socks_decode_error(c, r, __func__, "methods");
	සඳහා (found = i = 0; i < nmethods; i++) {
		නම් ((r = sshbuf_get_u8(b, &method)) != 0)
			ආපසු socks_decode_error(c, r, __func__, "method");
		නම් (method == SSH_SOCKS5_NOAUTH)
			found = 1;
	}
	නම් (!found) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		ආපසු -1;
	}
	/* Consume completed request */
	නම් ((r = sshbuf_consume_upto_child(input, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	නම් ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	ආපසු 1;
}

static පූර්ණ_සංඛ්‍යා
channel_decode_socks5(Channel *c, sa_nracanaa sshbuf *input, sa_nracanaa sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_port;
	var_na dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	පූර්ණ_සංඛ්‍යා r, success = -1;;
	sa_nracanaa sshbuf *b = NULL;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	නම් ((b = sshbuf_fromb(input)) == NULL)
		fatal_f("sshbuf_fromb failed");

	නම් (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		නම් ((r = channel_socks5_check_auth(c, b, input, output)) != 1) {
			success = r;
			goto out;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	නම් ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		goto out;
	}
	නම් (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	නම් ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		goto out;
	}

	නම් (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		goto out;
	}

	switch (socks_atyp) {
	pak_sa SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		bha_nga;
	pak_sa SSH_SOCKS5_DOMAIN:
		නම් ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			goto out;
		}
		af = -1;
		bha_nga;
	pak_sa SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		bha_nga;
	default:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		goto out;
	}
	නම් ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		goto out;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	නම් ((r = sshbuf_consume_upto_child(input, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	free(c->path);
	c->path = NULL;
	නම් (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->path = xstrdup(dest_addr);
	නැතහොත් {
		නම් (inet_ntop(af, dest_addr, ntop, parimaa_na(ntop)) == NULL)
			ආපසු -1;
		c->path = xstrdup(ntop);
	}
	c->host_port = dest_port;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->path, c->host_port, socks_cmd);

	/* Reply */
	නම් ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/* version */
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
	ආපසු success;
}

Channel *
channel_connect_stdio_fwd(sa_nracanaa ssh *ssh,
    const var_na *host_to_connect, පූර්ණ_සංඛ්‍යා port_to_connect,
    පූර්ණ_සංඛ්‍යා in, පූර්ණ_සංඛ්‍යා out, පූර්ණ_සංඛ්‍යා nonblock)
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

	ආපසු c;
}

/* dynamic port forwarding */
static void
channel_pre_dynamic(sa_nracanaa ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	පූර්ණ_සංඛ්‍යා r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->input);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	නම් (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		ආපසු;
	}
	/* try to guess the protocol */
	නම් ((r = sshbuf_peek_u8(c->input, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	switch (ver) {
	pak_sa 0x04:
		ret = channel_decode_socks4(c, c->input, c->output);
		bha_nga;
	pak_sa 0x05:
		ret = channel_decode_socks5(c, c->input, c->output);
		bha_nga;
	default:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		bha_nga;
	}
	නම් (ret < 0) {
		chan_mark_dead(ssh, c);
	} නැතහොත් නම් (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		නම් (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} නැතහොත් {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		port_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
static void
rdynamic_close(sa_nracanaa ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
static void
channel_before_prepare_io_rdynamic(sa_nracanaa ssh *ssh, Channel *c)
{
	const u_char *p;
	u_int have, len;
	පූර්ණ_සංඛ්‍යා r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	නම් (c->flags & CHAN_EOF_RCVD) {
		නම් ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		ආපසු;
	}
	/* check if the fixed size part of the packet is in buffer. */
	නම් (have < 3)
		ආපසු;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	switch (p[0]) {
	pak_sa 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->input);
		bha_nga;
	pak_sa 0x05:
		ret = channel_decode_socks5(c, c->output, c->input);
		bha_nga;
	default:
		ret = -1;
		bha_nga;
	}
	නම් (ret < 0) {
		rdynamic_close(ssh, c);
	} නැතහොත් නම් (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->input);
		නම් (len > 0 && len < c->remote_window) {
			නම් ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_DATA)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->input)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			නම් ((r = sshbuf_consume(c->input, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_window -= len;
		}
	} නැතහොත් නම් (rdynamic_connect_finish(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
static void
channel_post_x11_listener(sa_nracanaa ssh *ssh, Channel *c)
{
	Channel *nc;
	sa_nracanaa sockaddr_storage addr;
	පූර්ණ_සංඛ්‍යා r, newsock, oerrno, remote_port;
	socklen_t addrlen;
	var_na buf[16384], *remote_ipaddr;

	නම් ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ආපසු;

	debug("X11 connection requested.");
	addrlen = parimaa_na(addr);
	newsock = accept(c->sock, (sa_nracanaa sockaddr *)&addr, &addrlen);
	නම් (c->single_connection) {
		oerrno = errno;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		errno = oerrno;
	}
	නම් (newsock == -1) {
		නම් (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		නම් (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ආපසු;
	}
	set_nodelay(newsock);
	නම් (ssh->chanctxt->want_tcp_keepalive)
		set_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_port = get_peer_port(newsock);
	snprintf(buf, parimaa_na buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_port);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	නම් ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_port)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	නම් ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	free(remote_ipaddr);
}

static void
port_open_helper(sa_nracanaa ssh *ssh, Channel *c, var_na *rtype)
{
	var_na *local_ipaddr = get_local_ipaddr(c->sock);
	පූර්ණ_සංඛ්‍යා local_port = c->sock == -1 ? 65536 : get_local_port(c->sock);
	var_na *remote_ipaddr = get_peer_ipaddr(c->sock);
	පූර්ණ_සංඛ්‍යා remote_port = get_peer_port(c->sock);
	පූර්ණ_සංඛ්‍යා r;

	නම් (remote_port == -1) {
		/* Fake addr/port to appease peers that validate it (Tectia) */
		free(remote_ipaddr);
		remote_ipaddr = xstrdup("127.0.0.1");
		remote_port = 65535;
	}

	free(c->remote_name);
	xasprintf(&c->remote_name,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d to %.100s port %d",
	    rtype, c->listening_port, c->path, c->host_port,
	    remote_ipaddr, remote_port, local_ipaddr, local_port);

	open_preamble(ssh, __func__, c, rtype);
	නම් (strcmp(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		නම් ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} නැතහොත් නම් (strcmp(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		නම් ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} නැතහොත් නම් (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		නම් ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} නැතහොත් {
		/* listen address, port */
		නම් ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	නම් (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		නම් ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} නැතහොත් {
		/* originator host and port */
		නම් ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	නම් ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	free(remote_ipaddr);
	free(local_ipaddr);
}

void
channel_set_x11_refuse_time(sa_nracanaa ssh *ssh, dviguu_na refuse_time)
{
	ssh->chanctxt->x11_refuse_time = refuse_time;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
static void
channel_post_port_listener(sa_nracanaa ssh *ssh, Channel *c)
{
	Channel *nc;
	sa_nracanaa sockaddr_storage addr;
	පූර්ණ_සංඛ්‍යා newsock, nextstate;
	socklen_t addrlen;
	var_na *rtype;

	නම් ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ආපසු;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_port, c->path, c->host_port);

	නම් (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} නැතහොත් නම් (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} නැතහොත් නම් (c->host_port == PORT_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} නැතහොත් නම් (c->host_port == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} නැතහොත් {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = parimaa_na(addr);
	newsock = accept(c->sock, (sa_nracanaa sockaddr *)&addr, &addrlen);
	නම් (newsock == -1) {
		නම් (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		නම් (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ආපසු;
	}
	නම් (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		set_nodelay(newsock);
		නම් (ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_port = c->listening_port;
	nc->host_port = c->host_port;
	නම් (c->path != NULL)
		nc->path = xstrdup(c->path);

	නම් (nextstate != SSH_CHANNEL_DYNAMIC)
		port_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
static void
channel_post_auth_listener(sa_nracanaa ssh *ssh, Channel *c)
{
	Channel *nc;
	පූර්ණ_සංඛ්‍යා r, newsock;
	sa_nracanaa sockaddr_storage addr;
	socklen_t addrlen;

	නම් ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ආපසු;

	addrlen = parimaa_na(addr);
	newsock = accept(c->sock, (sa_nracanaa sockaddr *)&addr, &addrlen);
	නම් (newsock == -1) {
		error("accept from auth socket: %.100s", strerror(errno));
		නම් (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ආපසු;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	නම් ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

static void
channel_post_connecting(sa_nracanaa ssh *ssh, Channel *c)
{
	පූර්ණ_සංඛ්‍යා err = 0, sock, isopen, r;
	socklen_t sz = parimaa_na(err);

	නම් ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		ආපසු;
	නම් (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	නම් (c->connect_ctx == NULL)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_FINISH);

	නම් (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = errno;
		error("getsockopt SO_ERROR failed");
	}

	නම් (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		නම් (isopen) {
			/* no message necessary */
		} නැතහොත් {
			නම් ((r = sshpkt_start(ssh,
			    SSH2_MSG_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		ආපසු;
	}
	නම් (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		ආපසු;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, strerror(err));

	/* Try next address, if any */
	නම් ((sock = connect_next(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		නම් (isopen) {
			rdynamic_close(ssh, c);
		} නැතහොත් {
			නම් ((r = sshpkt_start(ssh,
			    SSH2_MSG_CHANNEL_OPEN_FAILURE)) != 0 ||
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

static පූර්ණ_සංඛ්‍යා
channel_handle_rfd(sa_nracanaa ssh *ssh, Channel *c)
{
	var_na buf[CHAN_RBUF];
	ssize_t len;
	පූර්ණ_සංඛ්‍යා r, force;
	size_t nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	පූර්ණ_සංඛ්‍යා pty_zeroread = 0;

#ifdef PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#endif

	force = c->isatty && c->detach_close && c->istate != CHAN_INPUT_CLOSED;

	නම් (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		ආපසු 1;
	නම් ((avail = sshbuf_avail(c->input)) == 0)
		ආපසු 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	නම් (!pty_zeroread && c->input_filter == NULL && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		නම් (c->type == SSH_CHANNEL_OPEN) {
			නම් ((have = sshbuf_len(c->input)) >= c->remote_window)
				ආපසු 1; /* shouldn't happen */
			නම් (maxlen > c->remote_window - have)
				maxlen = c->remote_window - have;
		}
		නම් (maxlen > avail)
			maxlen = avail;
		නම් ((r = sshbuf_read(c->rfd, c->input, maxlen, &nr)) != 0) {
			නම් (errno == EINTR || (!force &&
			    (errno == EAGAIN || errno == EWOULDBLOCK)))
				ආපසු 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			goto rfail;
		}
		නම් (nr != 0)
			channel_set_used_time(ssh, c);
		ආපසු 1;
	}

	errno = 0;
	len = read(c->rfd, buf, parimaa_na(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	නම් (pty_zeroread && len == 0 && errno != 0)
		len = -1;
	නම් (len == -1 && (errno == EINTR ||
	    ((errno == EAGAIN || errno == EWOULDBLOCK) && !force)))
		ආපසු 1;
	නම් (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : strerror(errno));
 rfail:
		නම් (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			ආපසු -1;
		} නැතහොත් {
			chan_read_failed(ssh, c);
		}
		ආපසු -1;
	}
	channel_set_used_time(ssh, c);
	නම් (c->input_filter != NULL) {
		නම් (c->input_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} නැතහොත් නම් (c->datagram) {
		නම් ((r = sshbuf_put_string(c->input, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} නැතහොත් නම් ((r = sshbuf_put(c->input, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	ආපසු 1;
}

static පූර්ණ_සංඛ්‍යා
channel_handle_wfd(sa_nracanaa ssh *ssh, Channel *c)
{
	sa_nracanaa termios tio;
	u_char *data = NULL, *buf; /* XXX const; need filter API change */
	size_t dlen, olen = 0;
	පූර්ණ_සංඛ්‍යා r, len;

	නම් ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		ආපසු 1;
	නම් (sshbuf_len(c->output) == 0)
		ආපසු 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	නම් (c->output_filter != NULL) {
		නම් ((buf = c->output_filter(ssh, c, &data, &dlen)) == NULL) {
			debug2("channel %d: filter stops", c->self);
			නම් (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			නැතහොත්
				chan_write_failed(ssh, c);
			ආපසු -1;
		}
	} නැතහොත් නම් (c->datagram) {
		නම් ((r = sshbuf_get_string(c->output, &data, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = data;
	} නැතහොත් {
		buf = data = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	නම් (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = write(c->wfd, buf, dlen);
		free(data);
		නම් (len == -1 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK))
			ආපසු 1;
		නම් (len <= 0)
			goto write_fail;
		goto out;
	}

#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	නම් (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#endif

	len = write(c->wfd, buf, dlen);
	නම් (len == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		ආපසු 1;
	නම් (len <= 0) {
 write_fail:
		නම් (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			ආපසු -1;
		} නැතහොත් {
			chan_write_failed(ssh, c);
		}
		ආපසු -1;
	}
	channel_set_used_time(ssh, c);
#ifndef BROKEN_TCGETATTR_ICANON
	නම් (c->isatty && dlen >= 1 && buf[0] != '\r') {
		නම් (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			නම් ((r = sshpkt_msg_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#endif /* BROKEN_TCGETATTR_ICANON */
	නම් ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 out:
	c->local_consumed += olen - sshbuf_len(c->output);

	ආපසු 1;
}

static පූර්ණ_සංඛ්‍යා
channel_handle_efd_write(sa_nracanaa ssh *ssh, Channel *c)
{
	පූර්ණ_සංඛ්‍යා r;
	ssize_t len;

	නම් ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		ආපසු 1;
	නම් (sshbuf_len(c->extended) == 0)
		ආපසු 1;

	len = write(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	නම් (len == -1 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		ආපසු 1;
	නම් (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} නැතහොත් {
		නම් ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_set_used_time(ssh, c);
	}
	ආපසු 1;
}

static පූර්ණ_සංඛ්‍යා
channel_handle_efd_read(sa_nracanaa ssh *ssh, Channel *c)
{
	var_na buf[CHAN_RBUF];
	ssize_t len;
	පූර්ණ_සංඛ්‍යා r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_INPUT_CLOSED;

	නම් (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		ආපසු 1;

	len = read(c->efd, buf, parimaa_na(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	නම් (len == -1 && (errno == EINTR || ((errno == EAGAIN ||
	    errno == EWOULDBLOCK) && !force)))
		ආපසු 1;
	නම් (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		ආපසු 1;
	}
	channel_set_used_time(ssh, c);
	නම් (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	නැතහොත් නම් ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	ආපසු 1;
}

static පූර්ණ_සංඛ්‍යා
channel_handle_efd(sa_nracanaa ssh *ssh, Channel *c)
{
	නම් (c->efd == -1)
		ආපසු 1;

	/** XXX handle drain efd, too */

	නම් (c->extended_usage == CHAN_EXTENDED_WRITE)
		ආපසු channel_handle_efd_write(ssh, c);
	නැතහොත් නම් (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		ආපසු channel_handle_efd_read(ssh, c);

	ආපසු 1;
}

static පූර්ණ_සංඛ්‍යා
channel_check_window(sa_nracanaa ssh *ssh, Channel *c)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD)) &&
	    ((c->local_window_max - c->local_window >
	    c->local_maxpacket*3) ||
	    c->local_window < c->local_window_max/2) &&
	    c->local_consumed > 0) {
		නම් (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		නම් ((r = sshpkt_start(ssh,
		    SSH2_MSG_CHANNEL_WINDOW_ADJUST)) != 0 ||
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
	ආපසු 1;
}

static void
channel_post_open(sa_nracanaa ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_window(ssh, c);
}

static u_int
read_mux(sa_nracanaa ssh *ssh, Channel *c, u_int need)
{
	var_na buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	පූර්ණ_සංඛ්‍යා r;

	නම් (sshbuf_len(c->input) < need) {
		rlen = need - sshbuf_len(c->input);
		len = read(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		නම් (len == -1 && (errno == EINTR || errno == EAGAIN))
			ආපසු sshbuf_len(c->input);
		නම් (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			ආපසු 0;
		} නැතහොත් නම් ((r = sshbuf_put(c->input, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	ආපසු sshbuf_len(c->input);
}

static void
channel_post_mux_client_read(sa_nracanaa ssh *ssh, Channel *c)
{
	u_int need;

	නම් ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		ආපසු;
	නම් (c->istate != CHAN_INPUT_OPEN && c->istate != CHAN_INPUT_WAIT_DRAIN)
		ආපසු;
	නම් (c->mux_pause)
		ආපසු;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	නම් (read_mux(ssh, c, 4) < 4) /* read header */
		ආපසු;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->input));
#define CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	නම් (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		ආපසු;
	}
	නම් (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		ආපසු;
	නම් (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		ආපසු;
	}
}

static void
channel_post_mux_client_write(sa_nracanaa ssh *ssh, Channel *c)
{
	ssize_t len;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		ආපසු;
	නම් (sshbuf_len(c->output) == 0)
		ආපසු;

	len = write(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	නම් (len == -1 && (errno == EINTR || errno == EAGAIN))
		ආපසු;
	නම් (len <= 0) {
		chan_mark_dead(ssh, c);
		ආපසු;
	}
	නම් ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

static void
channel_post_mux_client(sa_nracanaa ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

static void
channel_post_mux_listener(sa_nracanaa ssh *ssh, Channel *c)
{
	Channel *nc;
	sa_nracanaa sockaddr_storage addr;
	socklen_t addrlen;
	පූර්ණ_සංඛ්‍යා newsock;
	uid_t euid;
	gid_t egid;

	නම් ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		ආපසු;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, parimaa_na(addr));
	addrlen = parimaa_na(addr);
	නම් ((newsock = accept(c->sock, (sa_nracanaa sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", strerror(errno));
		නම් (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		ආපසු;
	}

	නම් (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", strerror(errno));
		close(newsock);
		ආපසු;
	}
	නම් ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		ආපසු;
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

static void
channel_handler_init(sa_nracanaa ssh_channels *sc)
{
	chan_fn **pre, **post;

	නම් ((pre = calloc(SSH_CHANNEL_MAX_TYPE, parimaa_na(*pre))) == NULL ||
	    (post = calloc(SSH_CHANNEL_MAX_TYPE, parimaa_na(*post))) == NULL)
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
static void
channel_garbage_collect(sa_nracanaa ssh *ssh, Channel *c)
{
	නම් (c == NULL)
		ආපසු;
	නම් (c->detach_user != NULL) {
		නම් (!chan_is_dead(ssh, c, c->detach_close))
			ආපසු;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, NULL);
		/* if we still have a callback */
		නම් (c->detach_user != NULL)
			ආපසු;
		debug2("channel %d: gc: user detached", c->self);
	}
	නම් (!chan_is_dead(ssh, c, 1))
		ආපසු;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

ga_nanaa channel_table { CHAN_PRE, CHAN_POST };

static void
channel_handler(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා table, sa_nracanaa timespec *timeout)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = table == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	dviguu_na now;

	now = monotime_double();
	සඳහා (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		නම් (c == NULL)
			continue;
		/* Count open channels in bulk state */
		නම් (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		නම් (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			continue;
		නම් (c->delayed) {
			නම් (table == CHAN_PRE)
				c->delayed = 0;
			නැතහොත්
				continue;
		}
		නම් (ftab[c->type] != NULL) {
			නම් (table == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				dviguu_na deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} නැතහොත් නම් (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				නම් (timeout != NULL &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} නැතහොත් නම් (timeout != NULL) {
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
static void
channel_before_prepare_io(sa_nracanaa ssh *ssh)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	සඳහා (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		නම් (c == NULL)
			continue;
		නම් (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

static void
dump_channel_poll(const var_na *func, const var_na *what, Channel *c,
    u_int pollfd_offset, sa_nracanaa pollfd *pfd)
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
static void
channel_prepare_pollfd(Channel *c, u_int *next_pollfd,
    sa_nracanaa pollfd *pfd, u_int npfd)
{
	u_int ev, p = *next_pollfd;

	නම් (c == NULL)
		ආපසු;
	නම් (p + 4 > npfd) {
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
	නම් (c->rfd != -1) {
		ev = 0;
		නම් ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		නම් (c->wfd == c->rfd) {
			නම් ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		නම් (c->efd == c->rfd) {
			නම් ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			නම් ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		නම් (c->sock == c->rfd) {
			නම් ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			නම් ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		නම් (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	නම් (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		නම් ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		නම් (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	නම් (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		නම් ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		නම් ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		නම් (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	නම් (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		නම් ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		නම් ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		නම් (ev != 0) {
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
void
channel_prepare_poll(sa_nracanaa ssh *ssh, sa_nracanaa pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, sa_nracanaa timespec *timeout)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	සඳහා (i = 0; i < sc->channels_alloc; i++) {
		නම් (sc->channels[i] == NULL)
			continue;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	නම් (sc->channels_alloc >= (INT_MAX / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	නම් (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, parimaa_na(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	නම් (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	සඳහා (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

static void
fd_ready(Channel *c, පූර්ණ_සංඛ්‍යා p, sa_nracanaa pollfd *pfds, u_int npfd, පූර්ණ_සංඛ්‍යා fd,
    const var_na *what, u_int revents_mask, u_int ready)
{
	sa_nracanaa pollfd *pfd = &pfds[p];

	නම් (fd == -1)
		ආපසු;
	නම් (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	නම් (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	නම් ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	නම් ((pfd->revents & (revents_mask|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
void
channel_after_poll(sa_nracanaa ssh *ssh, sa_nracanaa pollfd *pfd, u_int npfd)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	u_int i;
	පූර්ණ_සංඛ්‍යා p;
	Channel *c;

#ifdef DEBUG_CHANNEL_POLL
	සඳහා (p = 0; p < (පූර්ණ_සංඛ්‍යා)npfd; p++) {
		නම් (pfd[p].revents == 0)
			continue;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#endif

	/* Convert pollfd into c->io_ready */
	සඳහා (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		නම් (c == NULL)
			continue;
		/* if rfd is shared with efd/sock then wfd should be too */
		නම් (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		නම් (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			නම් (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			නම් (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			නම් (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		නම් (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		නම් (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		නම් (c->sock != -1 && c->sock != c->rfd &&
		    (p = c->pfds[3]) != -1) {
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockr", POLLIN, SSH_CHAN_IO_SOCK_R);
			fd_ready(c, p, pfd, npfd, c->sock,
			    "sockw", POLLOUT, SSH_CHAN_IO_SOCK_W);
			dump_channel_poll(__func__, "sock", c, p, pfd);
		}
	}
	channel_handler(ssh, CHAN_POST, NULL);
}

/*
 * Enqueue data for channels with open or draining c->input.
 * Returns non-zero if a packet was enqueued.
 */
static පූර්ණ_සංඛ්‍යා
channel_output_poll_input_open(sa_nracanaa ssh *ssh, Channel *c)
{
	size_t len, plen;
	const u_char *pkt;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((len = sshbuf_len(c->input)) == 0) {
		නම් (c->istate == CHAN_INPUT_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			නම් (CHANNEL_EFD_INPUT_ACTIVE(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			නැතහොත්
				chan_ibuf_empty(ssh, c);
		}
		ආපසු 0;
	}

	නම් (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	නම් (c->datagram) {
		/* Check datagram will fit; drop if not */
		නම් ((r = sshbuf_get_string_direct(c->input, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		නම් (plen > c->remote_window || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			ආපසු 0;
		}
		/* Enqueue it */
		නම් ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_DATA)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_window -= plen;
		ආපසු 1;
	}

	/* Enqueue packet for buffered data. */
	නම් (len > c->remote_window)
		len = c->remote_window;
	නම් (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	නම් (len == 0)
		ආපසු 0;
	නම් ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->input), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	නම් ((r = sshbuf_consume(c->input, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	ආපසු 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
static පූර්ණ_සංඛ්‍යා
channel_output_poll_extended_read(sa_nracanaa ssh *ssh, Channel *c)
{
	size_t len;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((len = sshbuf_len(c->extended)) == 0)
		ආපසු 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_window, sshbuf_len(c->extended), c->extended_usage);
	නම් (len > c->remote_window)
		len = c->remote_window;
	නම් (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	නම් (len == 0)
		ආපසු 0;
	නම් (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	නම් ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_EXTENDED_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_DATA_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	නම් ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	ආපසු 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
පූර්ණ_සංඛ්‍යා
channel_output_poll(sa_nracanaa ssh *ssh)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	පූර්ණ_සංඛ්‍යා ret = 0;

	සඳහා (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		නම් (c == NULL)
			continue;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		නම් (c->type != SSH_CHANNEL_OPEN)
			continue;
		නම් ((c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			continue;
		}

		/* Get the amount of buffered data for this channel. */
		නම් (c->istate == CHAN_INPUT_OPEN ||
		    c->istate == CHAN_INPUT_WAIT_DRAIN)
			ret |= channel_output_poll_input_open(ssh, c);
		/* Send extended data, i.e. stderr */
		නම් (!(c->flags & CHAN_EOF_SENT) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	ආපසු ret;
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
පූර්ණ_සංඛ්‍යා
channel_proxy_downstream(sa_nracanaa ssh *ssh, Channel *downstream)
{
	Channel *c = NULL;
	sa_nracanaa sshbuf *original = NULL, *modified = NULL;
	const u_char *cp;
	var_na *ctype = NULL, *listen_host = NULL;
	u_char type;
	size_t have;
	පූර්ණ_සංඛ්‍යා ret = -1, r;
	u_int id, remote_id, listen_port;

	/* sshbuf_dump(downstream->input, stderr); */
	නම් ((r = sshbuf_get_string_direct(downstream->input, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		ආපසු -1;
	}
	නම් (have < 2) {
		error_f("short message");
		ආපසු -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	නම් (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	switch (type) {
	pak_sa SSH2_MSG_CHANNEL_OPEN:
		නම් ((original = sshbuf_from(cp, have)) == NULL ||
		    (modified = sshbuf_new()) == NULL) {
			error_f("alloc");
			goto out;
		}
		නම් ((r = sshbuf_get_cstring(original, &ctype, NULL)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			goto out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		නම් ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			goto out;
		}
		bha_nga;
	pak_sa SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		නම් ((original = sshbuf_from(cp, have)) == NULL ||
		    (modified = sshbuf_new()) == NULL) {
			error_f("alloc");
			goto out;
		}
		නම් ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			goto out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, "mux-down-connect", 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;
		c->remote_id = remote_id;
		c->have_remote_id = 1;
		නම් ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			goto out;
		}
		bha_nga;
	pak_sa SSH2_MSG_GLOBAL_REQUEST:
		නම් ((original = sshbuf_from(cp, have)) == NULL) {
			error_f("alloc");
			goto out;
		}
		නම් ((r = sshbuf_get_cstring(original, &ctype, NULL)) != 0) {
			error_fr(r, "parse");
			goto out;
		}
		නම් (strcmp(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			goto out;
		}
		නම් ((r = sshbuf_get_u8(original, NULL)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, NULL)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_port)) != 0) {
			error_fr(r, "parse");
			goto out;
		}
		නම් (listen_port > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_port);
			goto out;
		}
		/* Record that connection to this host/port is permitted. */
		permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, NULL, (පූර්ණ_සංඛ්‍යා)listen_port, downstream);
		bha_nga;
	pak_sa SSH2_MSG_CHANNEL_CLOSE:
		නම් (have < 4)
			bha_nga;
		remote_id = PEEK_U32(cp);
		නම් ((c = channel_by_remote_id(ssh, remote_id)) != NULL) {
			නම් (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			නැතහොත්
				c->flags |= CHAN_CLOSE_SENT;
		}
		bha_nga;
	}
	නම් (modified) {
		නම් ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			goto out;
		}
	} නැතහොත් {
		නම් ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put(ssh, cp, have)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			goto out;
		}
	}
	ret = 0;
 out:
	free(ctype);
	free(listen_host);
	sshbuf_free(original);
	sshbuf_free(modified);
	ආපසු ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
පූර්ණ_සංඛ්‍යා
channel_proxy_upstream(Channel *c, පූර්ණ_සංඛ්‍යා type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	sa_nracanaa sshbuf *b = NULL;
	Channel *downstream;
	const u_char *cp = NULL;
	size_t len;
	පූර්ණ_සංඛ්‍යා r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	නම් (c == NULL || c->type != SSH_CHANNEL_MUX_PROXY)
		ආපසු 0;
	නම් ((downstream = c->mux_ctx) == NULL)
		ආපසු 0;
	switch (type) {
	pak_sa SSH2_MSG_CHANNEL_CLOSE:
	pak_sa SSH2_MSG_CHANNEL_DATA:
	pak_sa SSH2_MSG_CHANNEL_EOF:
	pak_sa SSH2_MSG_CHANNEL_EXTENDED_DATA:
	pak_sa SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
	pak_sa SSH2_MSG_CHANNEL_OPEN_FAILURE:
	pak_sa SSH2_MSG_CHANNEL_WINDOW_ADJUST:
	pak_sa SSH2_MSG_CHANNEL_SUCCESS:
	pak_sa SSH2_MSG_CHANNEL_FAILURE:
	pak_sa SSH2_MSG_CHANNEL_REQUEST:
		bha_nga;
	default:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		ආපසු 0;
	}
	නම් ((b = sshbuf_new()) == NULL) {
		error_f("alloc reply");
		goto out;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	නම් (cp == NULL) {
		error_f("no packet");
		goto out;
	}
	/* translate id and send to muxclient */
	නම් ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		goto out;
	}
	/* sshbuf_dump(b, stderr); */
	නම් (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 out:
	/* update state */
	switch (type) {
	pak_sa SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		නම් (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		bha_nga;
	pak_sa SSH2_MSG_CHANNEL_CLOSE:
		නම් (c->flags & CHAN_CLOSE_SENT)
			channel_free(ssh, c);
		නැතහොත්
			c->flags |= CHAN_CLOSE_RCVD;
		bha_nga;
	}
	sshbuf_free(b);
	ආපසු 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
static පූර්ණ_සංඛ්‍යා
channel_parse_id(sa_nracanaa ssh *ssh, const var_na *where, const var_na *what)
{
	uint32_t id;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	නම් (id > INT_MAX) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	ආපසු (පූර්ණ_සංඛ්‍යා)id;
}

/* Lookup a channel from an ID in the current packet */
static Channel *
channel_from_packet_id(sa_nracanaa ssh *ssh, const var_na *where, const var_na *what)
{
	පූර්ණ_සංඛ්‍යා id = channel_parse_id(ssh, where, what);
	Channel *c;

	නම් ((c = channel_lookup(ssh, id)) == NULL) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	ආපසු c;
}

පූර්ණ_සංඛ්‍යා
channel_input_data(පූර්ණ_සංඛ්‍යා type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	const u_char *data;
	size_t data_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	පූර්ණ_සංඛ්‍යා r;

	නම් (channel_proxy_upstream(c, type, seq, ssh))
		ආපසු 0;

	/* Ignore any data for non-open channels (might happen on close) */
	නම් (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_FINISH &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		ආපසු 0;

	/* Get the data. */
	නම් ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = data_len;
	නම් (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	නම් (c->ostate != CHAN_OUTPUT_OPEN) {
		නම් (win_len > c->local_window)
			c->local_window = 0;
		නැතහොත්
			c->local_window -= win_len;
		c->local_consumed += win_len;
		ආපසු 0;
	}

	නම් (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		ආපසු 0;
	}
	නම් (win_len > c->local_window) {
		u_int delta = win_len - c->local_window;

		නම් (c->local_window_exceeded > UINT_MAX - delta)
			c->local_window_exceeded = UINT_MAX;
		නැතහොත්
			c->local_window_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_window,
		    c->local_window_max, c->local_window_exceeded);
		c->local_window = 0;
		/* Allow 10% grace before bringing the hammer down */
		නම් (c->local_window_exceeded > (c->local_window_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} නැතහොත් {
		c->local_window -= win_len;
		c->local_window_exceeded = 0;
	}

	නම් (c->datagram) {
		නම් ((r = sshbuf_put_string(c->output, data, data_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} නැතහොත් නම් ((r = sshbuf_put(c->output, data, data_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
channel_input_extended_data(පූර්ණ_සංඛ්‍යා type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	const u_char *data;
	size_t data_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	පූර්ණ_සංඛ්‍යා r;

	නම් (channel_proxy_upstream(c, type, seq, ssh))
		ආපසු 0;
	නම් (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		ආපසු 0;
	}
	නම් (c->flags & CHAN_EOF_RCVD) {
		නම් (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		නැතහොත්
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	නම් ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	නම් (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_DATA_STDERR) {
		logit("channel %d: bad ext data", c->self);
		ආපසු 0;
	}
	නම් ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	නම් (data_len > c->local_window) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, data_len, c->local_window);
		ආපසු 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, data_len);
	/* XXX sshpkt_getb? */
	නම් ((r = sshbuf_put(c->extended, data, data_len)) != 0)
		error_fr(r, "append");
	c->local_window -= data_len;
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
channel_input_ieof(පූර්ණ_සංඛ්‍යා type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	පූර්ණ_සංඛ්‍යා r;

        නම් ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	නම් (channel_proxy_upstream(c, type, seq, ssh))
		ආපසු 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	නම් (c->force_drain && c->istate == CHAN_INPUT_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_INPUT_WAIT_DRAIN;
		නම් (sshbuf_len(c->input) == 0)
			chan_ibuf_empty(ssh, c);
	}
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
channel_input_oclose(පූර්ණ_සංඛ්‍යා type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	පූර්ණ_සංඛ්‍යා r;

	නම් (channel_proxy_upstream(c, type, seq, ssh))
		ආපසු 0;
        නම් ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
channel_input_open_confirmation(පූර්ණ_සංඛ්‍යා type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_window, remote_maxpacket;
	පූර්ණ_සංඛ්‍යා r;

	නම් (channel_proxy_upstream(c, type, seq, ssh))
		ආපසු 0;
	නම් (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	නම් ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
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
	නම් (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_set_used_time(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_window, c->remote_maxpacket);
	ආපසු 0;
}

static var_na *
reason2txt(පූර්ණ_සංඛ්‍යා reason)
{
	switch (reason) {
	pak_sa SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		ආපසු "administratively prohibited";
	pak_sa SSH2_OPEN_CONNECT_FAILED:
		ආපසු "connect failed";
	pak_sa SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		ආපසු "unknown channel type";
	pak_sa SSH2_OPEN_RESOURCE_SHORTAGE:
		ආපසු "resource shortage";
	}
	ආපසු "unknown reason";
}

පූර්ණ_සංඛ්‍යා
channel_input_open_failure(පූර්ණ_සංඛ්‍යා type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	var_na *msg = NULL;
	පූර්ණ_සංඛ්‍යා r;

	නම් (channel_proxy_upstream(c, type, seq, ssh))
		ආපසු 0;
	නම් (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	නම් ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	නම් ((r = sshpkt_get_cstring(ssh, &msg, NULL)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, NULL, NULL)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), msg ? ": ": "", msg ? msg : "");
	free(msg);
	නම් (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
channel_input_window_adjust(පූර්ණ_සංඛ්‍යා type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	පූර්ණ_සංඛ්‍යා id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((c = channel_lookup(ssh, id)) == NULL) {
		logit("Received window adjust for non-open channel %d.", id);
		ආපසු 0;
	}

	නම් (channel_proxy_upstream(c, type, seq, ssh))
		ආපසු 0;
	නම් ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	නම් ((new_rwin = c->remote_window + adjust) < c->remote_window) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_window);
	}
	c->remote_window = new_rwin;
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
channel_input_status_confirm(පූර්ණ_සංඛ්‍යා type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	පූර්ණ_සංඛ්‍යා id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	sa_nracanaa channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_set_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	නම් ((c = channel_lookup(ssh, id)) == NULL) {
		logit_f("%d: unknown", id);
		ආපසු 0;
	}
	නම් (channel_proxy_upstream(c, type, seq, ssh))
		ආපසු 0;
        නම් (sshpkt_get_end(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	නම් ((cc = TAILQ_FIRST(&c->status_confirms)) == NULL)
		ආපසු 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->status_confirms, cc, entry);
	freezero(cc, parimaa_na(*cc));
	ආපසු 0;
}

/* -- tcp forwarding */

void
channel_set_af(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා af)
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
static const var_na *
channel_fwd_bind_addr(sa_nracanaa ssh *ssh, const var_na *listen_addr, පූර්ණ_සංඛ්‍යා *wildcardp,
    පූර්ණ_සංඛ්‍යා is_client, sa_nracanaa ForwardOptions *fwd_opts)
{
	const var_na *addr = NULL;
	පූර්ණ_සංඛ්‍යා wildcard = 0;

	නම් (listen_addr == NULL) {
		/* No address specified: default to gateway_ports setting */
		නම් (fwd_opts->gateway_ports)
			wildcard = 1;
	} නැතහොත් නම් (fwd_opts->gateway_ports || is_client) {
		නම් (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			නම් (*listen_addr != '\0' &&
			    strcmp(listen_addr, "0.0.0.0") != 0 &&
			    strcmp(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} නැතහොත් නම් (strcmp(listen_addr, "localhost") != 0 ||
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
	} නැතහොත් නම් (strcmp(listen_addr, "127.0.0.1") == 0 ||
	    strcmp(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	නම් (wildcardp != NULL)
		*wildcardp = wildcard;
	ආපසු addr;
}

static පූර්ණ_සංඛ්‍යා
channel_setup_fwd_listener_tcpip(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා type,
    sa_nracanaa Forward *fwd, පූර්ණ_සංඛ්‍යා *allocated_listen_port,
    sa_nracanaa ForwardOptions *fwd_opts)
{
	Channel *c;
	පූර්ණ_සංඛ්‍යා sock, r, success = 0, wildcard = 0, is_client;
	sa_nracanaa addrinfo hints, *ai, *aitop;
	const var_na *host, *addr;
	var_na ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_PORT_LISTENER);

	නම් (is_client && fwd->connect_path != NULL) {
		host = fwd->connect_path;
	} නැතහොත් {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		නම් (host == NULL) {
			error("No forward host name.");
			ආපසු 0;
		}
		නම් (strlen(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			ආපසු 0;
		}
	}

	/* Determine the bind address, cf. channel_fwd_bind_addr() comment */
	addr = channel_fwd_bind_addr(ssh, fwd->listen_host, &wildcard,
	    is_client, fwd_opts);
	debug3_f("type %d wildcard %d addr %s", type, wildcard,
	    (addr == NULL) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, parimaa_na(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, parimaa_na strport, "%d", fwd->listen_port);
	නම් ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		නම් (addr == NULL) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} නැතහොත් {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		ආපසු 0;
	}
	නම් (allocated_listen_port != NULL)
		*allocated_listen_port = 0;
	සඳහා (ai = aitop; ai; ai = ai->ai_next) {
		switch (ai->ai_family) {
		pak_sa AF_INET:
			lport_p = &((sa_nracanaa sockaddr_in *)ai->ai_addr)->
			    sin_port;
			bha_nga;
		pak_sa AF_INET6:
			lport_p = &((sa_nracanaa sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			bha_nga;
		default:
			continue;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		නම් (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 && allocated_listen_port != NULL &&
		    *allocated_listen_port > 0)
			*lport_p = htons(*allocated_listen_port);

		නම් (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, parimaa_na(ntop),
		    strport, parimaa_na(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			continue;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		නම් (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			continue;
		}

		set_reuseaddr(sock);
		නම් (ai->ai_family == AF_INET6)
			sock_set_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		නම් (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			නම් (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));
			නැතහොත්
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));

			close(sock);
			continue;
		}
		/* Start listening for connections on the socket. */
		නම් (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			close(sock);
			continue;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		නම් (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 &&
		    allocated_listen_port != NULL &&
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
		c->listening_addr = addr == NULL ? NULL : xstrdup(addr);
		නම් (fwd->listen_port == 0 && allocated_listen_port != NULL &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_port = *allocated_listen_port;
		නැතහොත්
			c->listening_port = fwd->listen_port;
		success = 1;
	}
	නම් (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_port);
	freeaddrinfo(aitop);
	ආපසු success;
}

static පූර්ණ_සංඛ්‍යා
channel_setup_fwd_listener_streamlocal(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා type,
    sa_nracanaa Forward *fwd, sa_nracanaa ForwardOptions *fwd_opts)
{
	sa_nracanaa sockaddr_un sunaddr;
	const var_na *path;
	Channel *c;
	පූර්ණ_සංඛ්‍යා port, sock;
	mode_t omask;

	switch (type) {
	pak_sa SSH_CHANNEL_UNIX_LISTENER:
		නම් (fwd->connect_path != NULL) {
			නම් (strlen(fwd->connect_path) > parimaa_na(sunaddr.sun_path)) {
				error("Local connecting path too long: %s",
				    fwd->connect_path);
				ආපසු 0;
			}
			path = fwd->connect_path;
			port = PORT_STREAMLOCAL;
		} නැතහොත් {
			නම් (fwd->connect_host == NULL) {
				error("No forward host name.");
				ආපසු 0;
			}
			නම් (strlen(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				ආපසු 0;
			}
			path = fwd->connect_host;
			port = fwd->connect_port;
		}
		bha_nga;
	pak_sa SSH_CHANNEL_RUNIX_LISTENER:
		path = fwd->listen_path;
		port = PORT_STREAMLOCAL;
		bha_nga;
	default:
		error_f("unexpected channel type %d", type);
		ආපසු 0;
	}

	නම් (fwd->listen_path == NULL) {
		error("No forward path name.");
		ආපසු 0;
	}
	නම් (strlen(fwd->listen_path) > parimaa_na(sunaddr.sun_path)) {
		error("Local listening path too long: %s", fwd->listen_path);
		ආපසු 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_path);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_mask);
	sock = unix_listener(fwd->listen_path, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	නම් (sock < 0)
		ආපසු 0;

	debug("Local forwarding listening on path %s.", fwd->listen_path);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->path = xstrdup(path);
	c->host_port = port;
	c->listening_port = PORT_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_path);
	ආපසු 1;
}

static පූර්ණ_සංඛ්‍යා
channel_cancel_rport_listener_tcpip(sa_nracanaa ssh *ssh,
    const var_na *host, u_short port)
{
	u_int i;
	පූර්ණ_සංඛ්‍යා found = 0;

	සඳහා (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		නම් (c == NULL || c->type != SSH_CHANNEL_RPORT_LISTENER)
			continue;
		නම් (strcmp(c->path, host) == 0 && c->listening_port == port) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ආපසු found;
}

static පූර්ණ_සංඛ්‍යා
channel_cancel_rport_listener_streamlocal(sa_nracanaa ssh *ssh, const var_na *path)
{
	u_int i;
	පූර්ණ_සංඛ්‍යා found = 0;

	සඳහා (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		නම් (c == NULL || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			continue;
		නම් (c->path == NULL)
			continue;
		නම් (strcmp(c->path, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ආපසු found;
}

පූර්ණ_සංඛ්‍යා
channel_cancel_rport_listener(sa_nracanaa ssh *ssh, sa_nracanaa Forward *fwd)
{
	නම් (fwd->listen_path != NULL) {
		ආපසු channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} නැතහොත් {
		ආපසු channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port);
	}
}

static පූර්ණ_සංඛ්‍යා
channel_cancel_lport_listener_tcpip(sa_nracanaa ssh *ssh,
    const var_na *lhost, u_short lport, පූර්ණ_සංඛ්‍යා cport,
    sa_nracanaa ForwardOptions *fwd_opts)
{
	u_int i;
	පූර්ණ_සංඛ්‍යා found = 0;
	const var_na *addr = channel_fwd_bind_addr(ssh, lhost, NULL, 1, fwd_opts);

	සඳහා (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		නම් (c == NULL || c->type != SSH_CHANNEL_PORT_LISTENER)
			continue;
		නම් (c->listening_port != lport)
			continue;
		නම් (cport == CHANNEL_CANCEL_PORT_STATIC) {
			/* skip dynamic forwardings */
			නම් (c->host_port == 0)
				continue;
		} නැතහොත් {
			නම් (c->host_port != cport)
				continue;
		}
		නම් ((c->listening_addr == NULL && addr != NULL) ||
		    (c->listening_addr != NULL && addr == NULL))
			continue;
		නම් (addr == NULL || strcmp(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ආපසු found;
}

static පූර්ණ_සංඛ්‍යා
channel_cancel_lport_listener_streamlocal(sa_nracanaa ssh *ssh, const var_na *path)
{
	u_int i;
	පූර්ණ_සංඛ්‍යා found = 0;

	නම් (path == NULL) {
		error_f("no path specified.");
		ආපසු 0;
	}

	සඳහා (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		නම් (c == NULL || c->type != SSH_CHANNEL_UNIX_LISTENER)
			continue;
		නම් (c->listening_addr == NULL)
			continue;
		නම් (strcmp(c->listening_addr, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	ආපසු found;
}

පූර්ණ_සංඛ්‍යා
channel_cancel_lport_listener(sa_nracanaa ssh *ssh,
    sa_nracanaa Forward *fwd, පූර්ණ_සංඛ්‍යා cport, sa_nracanaa ForwardOptions *fwd_opts)
{
	නම් (fwd->listen_path != NULL) {
		ආපසු channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} නැතහොත් {
		ආපසු channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
පූර්ණ_සංඛ්‍යා
channel_setup_local_fwd_listener(sa_nracanaa ssh *ssh,
    sa_nracanaa Forward *fwd, sa_nracanaa ForwardOptions *fwd_opts)
{
	නම් (fwd->listen_path != NULL) {
		ආපසු channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} නැතහොත් {
		ආපසු channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_PORT_LISTENER, fwd, NULL, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
static පූර්ණ_සංඛ්‍යා
remote_open_match(sa_nracanaa permission *allowed_open, sa_nracanaa Forward *fwd)
{
	පූර්ණ_සංඛ්‍යා ret;
	var_na *lhost;

	/* XXX add ACLs for streamlocal */
	නම් (fwd->listen_path != NULL)
		ආපසු 1;

	නම් (fwd->listen_host == NULL || allowed_open->listen_host == NULL)
		ආපසු 0;

	නම් (allowed_open->listen_port != FWD_PERMIT_ANY_PORT &&
	    allowed_open->listen_port != fwd->listen_port)
		ආපසු 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = match_pattern(lhost, allowed_open->listen_host);
	free(lhost);

	ආපසු ret;
}

/* Checks whether a requested remote forwarding is permitted */
static පූර්ණ_සංඛ්‍යා
check_rfwd_permission(sa_nracanaa ssh *ssh, sa_nracanaa Forward *fwd)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	sa_nracanaa permission_set *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	sa_nracanaa permission *perm;

#ifdef SKIP_PRIVDROP
	නම් (fwd->listen_path != NULL)
		ආපසු 0;
	නම් (fwd->listen_port != 0 && fwd->listen_port < 1024)
		ආපසු 0;
#endif

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	නම් (!permit) {
		සඳහා (i = 0; i < pset->num_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			නම් (remote_open_match(perm, fwd)) {
				permit = 1;
				bha_nga;
			}
		}
	}

	නම් (pset->num_permitted_admin > 0) {
		permit_adm = 0;
		සඳහා (i = 0; i < pset->num_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			නම් (remote_open_match(perm, fwd)) {
				permit_adm = 1;
				bha_nga;
			}
		}
	}

	ආපසු permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
පූර්ණ_සංඛ්‍යා
channel_setup_remote_fwd_listener(sa_nracanaa ssh *ssh, sa_nracanaa Forward *fwd,
    පූර්ණ_සංඛ්‍යා *allocated_listen_port, sa_nracanaa ForwardOptions *fwd_opts)
{
	නම් (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		නම් (fwd->listen_path != NULL)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_path);
		නැතහොත් නම්(fwd->listen_host != NULL)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_host, fwd->listen_port );
		නැතහොත්
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		ආපසු 0;
	}
	නම් (fwd->listen_path != NULL) {
		ආපසු channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} නැතහොත් {
		ආපසු channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_port,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
static const var_na *
channel_rfwd_bind_host(const var_na *listen_host)
{
	නම් (listen_host == NULL) {
		ආපසු "localhost";
	} නැතහොත් නම් (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		ආපසු "";
	} නැතහොත්
		ආපසු listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
පූර්ණ_සංඛ්‍යා
channel_request_remote_forwarding(sa_nracanaa ssh *ssh, sa_nracanaa Forward *fwd)
{
	පූර්ණ_සංඛ්‍යා r, success = 0, idx = -1;
	const var_na *host_to_connect, *listen_host, *listen_path;
	පූර්ණ_සංඛ්‍යා port_to_connect, listen_port;

	/* Send the forward request to the remote side. */
	නම් (fwd->listen_path != NULL) {
		නම් ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_path)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} නැතහොත් {
		නම් ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
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
	නම් (success) {
		/* Record that connection to this host/port is permitted. */
		host_to_connect = listen_host = listen_path = NULL;
		port_to_connect = listen_port = 0;
		නම් (fwd->connect_path != NULL) {
			host_to_connect = fwd->connect_path;
			port_to_connect = PORT_STREAMLOCAL;
		} නැතහොත් {
			host_to_connect = fwd->connect_host;
			port_to_connect = fwd->connect_port;
		}
		නම් (fwd->listen_path != NULL) {
			listen_path = fwd->listen_path;
			listen_port = PORT_STREAMLOCAL;
		} නැතහොත් {
			listen_host = fwd->listen_host;
			listen_port = fwd->listen_port;
		}
		idx = permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_to_connect, port_to_connect,
		    listen_host, listen_path, listen_port, NULL);
	}
	ආපසු idx;
}

static පූර්ණ_සංඛ්‍යා
open_match(sa_nracanaa permission *allowed_open, const var_na *requestedhost,
    පූර්ණ_සංඛ්‍යා requestedport)
{
	නම් (allowed_open->host_to_connect == NULL)
		ආපසු 0;
	නම් (allowed_open->port_to_connect != FWD_PERMIT_ANY_PORT &&
	    allowed_open->port_to_connect != requestedport)
		ආපසු 0;
	නම් (strcmp(allowed_open->host_to_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    strcmp(allowed_open->host_to_connect, requestedhost) != 0)
		ආපසු 0;
	ආපසු 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
static පූර්ණ_සංඛ්‍යා
open_listen_match_tcpip(sa_nracanaa permission *allowed_open,
    const var_na *requestedhost, u_short requestedport, පූර්ණ_සංඛ්‍යා translate)
{
	const var_na *allowed_host;

	නම් (allowed_open->host_to_connect == NULL)
		ආපසු 0;
	නම් (allowed_open->listen_port != requestedport)
		ආපසු 0;
	නම් (!translate && allowed_open->listen_host == NULL &&
	    requestedhost == NULL)
		ආපසු 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	නම් (allowed_host == NULL || requestedhost == NULL ||
	    strcmp(allowed_host, requestedhost) != 0)
		ආපසු 0;
	ආපසු 1;
}

static පූර්ණ_සංඛ්‍යා
open_listen_match_streamlocal(sa_nracanaa permission *allowed_open,
    const var_na *requestedpath)
{
	නම් (allowed_open->host_to_connect == NULL)
		ආපසු 0;
	නම් (allowed_open->listen_port != PORT_STREAMLOCAL)
		ආපසු 0;
	නම් (allowed_open->listen_path == NULL ||
	    strcmp(allowed_open->listen_path, requestedpath) != 0)
		ආපසු 0;
	ආපසු 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
static පූර්ණ_සංඛ්‍යා
channel_request_rforward_cancel_tcpip(sa_nracanaa ssh *ssh,
    const var_na *host, u_short port)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	sa_nracanaa permission_set *pset = &sc->local_perms;
	පූර්ණ_සංඛ්‍යා r;
	u_int i;
	sa_nracanaa permission *perm = NULL;

	සඳහා (i = 0; i < pset->num_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		නම් (open_listen_match_tcpip(perm, host, port, 0))
			bha_nga;
		perm = NULL;
	}
	නම් (perm == NULL) {
		debug_f("requested forward not found");
		ආපසු -1;
	}
	නම් ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, port)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	ආපසු 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
static පූර්ණ_සංඛ්‍යා
channel_request_rforward_cancel_streamlocal(sa_nracanaa ssh *ssh, const var_na *path)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	sa_nracanaa permission_set *pset = &sc->local_perms;
	පූර්ණ_සංඛ්‍යා r;
	u_int i;
	sa_nracanaa permission *perm = NULL;

	සඳහා (i = 0; i < pset->num_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		නම් (open_listen_match_streamlocal(perm, path))
			bha_nga;
		perm = NULL;
	}
	නම් (perm == NULL) {
		debug_f("requested forward not found");
		ආපසු -1;
	}
	නම් ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, path)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	ආපසු 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
පූර්ණ_සංඛ්‍යා
channel_request_rforward_cancel(sa_nracanaa ssh *ssh, sa_nracanaa Forward *fwd)
{
	නම් (fwd->listen_path != NULL) {
		ආපසු channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_path);
	} නැතහොත් {
		ආපසු channel_request_rforward_cancel_tcpip(ssh,
		    fwd->listen_host,
		    fwd->listen_port ? fwd->listen_port : fwd->allocated_port);
	}
}

/*
 * Permits opening to any host/port if permitted_user[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
void
channel_permit_all(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා where)
{
	sa_nracanaa permission_set *pset = permission_set_get(ssh, where);

	නම් (pset->num_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
void
channel_add_permission(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා who, පූර්ණ_සංඛ්‍යා where,
    var_na *host, පූර්ණ_සංඛ්‍යා port)
{
	පූර්ණ_සංඛ්‍යා local = where == FORWARD_LOCAL;
	sa_nracanaa permission_set *pset = permission_set_get(ssh, where);

	debug("allow %s forwarding to host %s port %d",
	    fwd_ident(who, where), host, port);
	/*
	 * Remote forwards set listen_host/port, local forwards set
	 * host/port_to_connect.
	 */
	permission_set_add(ssh, who, where,
	    local ? host : NULL, local ? port : 0,
	    local ? NULL : host, NULL, local ? 0 : port, NULL);
	pset->all_permitted = 0;
}

/*
 * Administratively disable forwarding.
 */
void
channel_disable_admin(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_set_add(ssh, FORWARD_ADM, where,
	    NULL, 0, NULL, NULL, 0, NULL);
}

/*
 * Clear a list of permitted opens.
 */
void
channel_clear_permission(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා who, පූර්ණ_සංඛ්‍යා where)
{
	sa_nracanaa permission **permp;
	u_int i, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);
	සඳහා (i = 0; i < *npermp; i++)
		fwd_perm_clear((*permp) + i);
	free(*permp);
	*permp = NULL;
	*npermp = 0;
}

/*
 * Update the listen port for a dynamic remote forward, after
 * the actual 'newport' has been allocated. If 'newport' < 0 is
 * passed then they entry will be invalidated.
 */
void
channel_update_permission(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා idx, පූර්ණ_සංඛ්‍යා newport)
{
	sa_nracanaa permission_set *pset = &ssh->chanctxt->local_perms;

	නම් (idx < 0 || (u_int)idx >= pset->num_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->num_permitted_user);
		ආපසු;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_to_connect,
	    pset->permitted_user[idx].port_to_connect);
	නම් (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	නැතහොත් {
		pset->permitted_user[idx].listen_port =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
static පූර්ණ_සංඛ්‍යා
connect_next(sa_nracanaa ssh *ssh, sa_nracanaa channel_connect *cctx)
{
	පූර්ණ_සංඛ්‍යා sock, sock_is_network, saved_errno;
	sa_nracanaa sockaddr_un *sunaddr;
	var_na ntop[NI_MAXHOST];
	var_na strport[MAXIMUM(NI_MAXSERV, parimaa_na(sunaddr->sun_path))];

	සඳහා (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_network = 0;
		switch (cctx->ai->ai_family) {
		pak_sa AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (sa_nracanaa sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", parimaa_na(ntop));
			strlcpy(strport, sunaddr->sun_path, parimaa_na(strport));
			bha_nga;
		pak_sa AF_INET:
		pak_sa AF_INET6:
			නම් (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, parimaa_na(ntop), strport, parimaa_na(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				continue;
			}
			sock_is_network = 1;
			bha_nga;
		default:
			continue;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		නම් ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			නම් (cctx->ai->ai_next == NULL)
				error("socket: %.100s", strerror(errno));
			නැතහොත්
				verbose("socket: %.100s", strerror(errno));
			continue;
		}
		නම් (set_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		නම් (sock_is_network && ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(sock); /* logs errors */
		නම් (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			continue;	/* fail -- try next */
		}
		නම් (cctx->ai->ai_family != AF_UNIX)
			set_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		ආපසු sock;
	}
	ආපසු -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
static පූර්ණ_සංඛ්‍යා
connect_to_helper(sa_nracanaa ssh *ssh, const var_na *name, පූර්ණ_සංඛ්‍යා port, පූර්ණ_සංඛ්‍යා socktype,
    var_na *ctype, var_na *rname, sa_nracanaa channel_connect *cctx,
    පූර්ණ_සංඛ්‍යා *reason, const var_na **errmsg)
{
	sa_nracanaa addrinfo hints;
	පූර්ණ_සංඛ්‍යා gaierr;
	පූර්ණ_සංඛ්‍යා sock = -1;
	var_na strport[NI_MAXSERV];

	නම් (port == PORT_STREAMLOCAL) {
		sa_nracanaa sockaddr_un *sunaddr;
		sa_nracanaa addrinfo *ai;

		නම් (strlen(name) > parimaa_na(sunaddr->sun_path)) {
			error("%.100s: %.100s", name, strerror(ENAMETOOLONG));
			ආපසු -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, parimaa_na(*ai) + parimaa_na(*sunaddr));
		ai->ai_addr = (sa_nracanaa sockaddr *)(ai + 1);
		ai->ai_addrlen = parimaa_na(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (sa_nracanaa sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_path, name, parimaa_na(sunaddr->sun_path));
		cctx->aitop = ai;
	} නැතහොත් {
		memset(&hints, 0, parimaa_na(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, parimaa_na strport, "%d", port);
		නම් ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			නම් (errmsg != NULL)
				*errmsg = ssh_gai_strerror(gaierr);
			නම් (reason != NULL)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			ආපසු -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->port = port;
	cctx->ai = cctx->aitop;

	නම් ((sock = connect_next(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, port, strerror(errno));
		ආපසු -1;
	}

	ආපසු sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
static Channel *
connect_to(sa_nracanaa ssh *ssh, const var_na *host, පූර්ණ_සංඛ්‍යා port,
    var_na *ctype, var_na *rname)
{
	sa_nracanaa channel_connect cctx;
	Channel *c;
	පූර්ණ_සංඛ්‍යා sock;

	memset(&cctx, 0, parimaa_na(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, NULL, NULL);
	නම් (sock == -1) {
		free_connect_ctx(&cctx);
		ආපසු NULL;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(parimaa_na(cctx));
	memcpy(c->connect_ctx, &cctx, parimaa_na(cctx));

	ආපසු c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_address(sa_nracanaa ssh *ssh, const var_na *listen_host,
    u_short listen_port, var_na *ctype, var_na *rname)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	sa_nracanaa permission_set *pset = &sc->local_perms;
	u_int i;
	sa_nracanaa permission *perm;

	සඳහා (i = 0; i < pset->num_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		නම් (open_listen_match_tcpip(perm,
		    listen_host, listen_port, 1)) {
			නම් (perm->downstream)
				ආපසු perm->downstream;
			නම් (perm->port_to_connect == 0)
				ආපසු rdynamic_connect_prepare(ssh,
				    ctype, rname);
			ආපසු connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_port);
	ආපසු NULL;
}

Channel *
channel_connect_by_listen_path(sa_nracanaa ssh *ssh, const var_na *path,
    var_na *ctype, var_na *rname)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	sa_nracanaa permission_set *pset = &sc->local_perms;
	u_int i;
	sa_nracanaa permission *perm;

	සඳහා (i = 0; i < pset->num_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		නම් (open_listen_match_streamlocal(perm, path)) {
			ආපසු connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    path);
	ආපසු NULL;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_to_port(sa_nracanaa ssh *ssh, const var_na *host, u_short port,
    var_na *ctype, var_na *rname, පූර්ණ_සංඛ්‍යා *reason, const var_na **errmsg)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	sa_nracanaa permission_set *pset = &sc->local_perms;
	sa_nracanaa channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	පූර්ණ_සංඛ්‍යා sock;
	sa_nracanaa permission *perm;

	permit = pset->all_permitted;
	නම් (!permit) {
		සඳහා (i = 0; i < pset->num_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			නම් (open_match(perm, host, port)) {
				permit = 1;
				bha_nga;
			}
		}
	}

	නම් (pset->num_permitted_admin > 0) {
		permit_adm = 0;
		සඳහා (i = 0; i < pset->num_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			නම් (open_match(perm, host, port)) {
				permit_adm = 1;
				bha_nga;
			}
		}
	}

	නම් (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), host, port);
		නම් (reason != NULL)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		ආපසු NULL;
	}

	memset(&cctx, 0, parimaa_na(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	නම් (sock == -1) {
		free_connect_ctx(&cctx);
		ආපසු NULL;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(parimaa_na(cctx));
	memcpy(c->connect_ctx, &cctx, parimaa_na(cctx));

	ආපසු c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_to_path(sa_nracanaa ssh *ssh, const var_na *path,
    var_na *ctype, var_na *rname)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	sa_nracanaa permission_set *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	sa_nracanaa permission *perm;

	permit = pset->all_permitted;
	නම් (!permit) {
		සඳහා (i = 0; i < pset->num_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			නම් (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit = 1;
				bha_nga;
			}
		}
	}

	නම් (pset->num_permitted_admin > 0) {
		permit_adm = 0;
		සඳහා (i = 0; i < pset->num_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			නම් (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit_adm = 1;
				bha_nga;
			}
		}
	}

	නම් (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", path);
		ආපසු NULL;
	}
	ආපසු connect_to(ssh, path, PORT_STREAMLOCAL, ctype, rname);
}

void
channel_send_window_changes(sa_nracanaa ssh *ssh)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	sa_nracanaa winsize ws;
	පූර්ණ_සංඛ්‍යා r;
	u_int i;

	සඳහා (i = 0; i < sc->channels_alloc; i++) {
		නම් (sc->channels[i] == NULL || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			continue;
		නම් (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			continue;
		channel_request_start(ssh, i, "window-change", 0);
		නම් ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
static Channel *
rdynamic_connect_prepare(sa_nracanaa ssh *ssh, var_na *ctype, var_na *rname)
{
	Channel *c;
	පූර්ණ_සංඛ්‍යා r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = 0;
	c->path = NULL;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	නම් ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	ආපසු c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
static පූර්ණ_සංඛ්‍යා
rdynamic_connect_finish(sa_nracanaa ssh *ssh, Channel *c)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	sa_nracanaa permission_set *pset = &sc->local_perms;
	sa_nracanaa permission *perm;
	sa_nracanaa channel_connect cctx;
	u_int i, permit_adm = 1;
	පූර්ණ_සංඛ්‍යා sock;

	නම් (pset->num_permitted_admin > 0) {
		permit_adm = 0;
		සඳහා (i = 0; i < pset->num_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			නම් (open_match(perm, c->path, c->host_port)) {
				permit_adm = 1;
				bha_nga;
			}
		}
	}
	නම් (!permit_adm) {
		debug_f("requested forward not permitted");
		ආපසු -1;
	}

	memset(&cctx, 0, parimaa_na(cctx));
	sock = connect_to_helper(ssh, c->path, c->host_port, SOCK_STREAM, NULL,
	    NULL, &cctx, NULL, NULL);
	නම් (sock == -1)
		free_connect_ctx(&cctx);
	නැතහොත් {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_FINISH;
		c->connect_ctx = xmalloc(parimaa_na(cctx));
		memcpy(c->connect_ctx, &cctx, parimaa_na(cctx));
		channel_register_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	ආපසු sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
පූර්ණ_සංඛ්‍යා
x11_create_display_inet(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා x11_display_offset,
    පූර්ණ_සංඛ්‍යා x11_use_localhost, පූර්ණ_සංඛ්‍යා single_connection,
    u_int *display_numberp, පූර්ණ_සංඛ්‍යා **chanids)
{
	Channel *nc = NULL;
	පූර්ණ_සංඛ්‍යා display_number, sock, port;
	sa_nracanaa addrinfo hints, *ai, *aitop;
	var_na strport[NI_MAXSERV];
	පූර්ණ_සංඛ්‍යා gaierr, n, num_socks = 0, socks[NUM_SOCKS];

	නම් (chanids == NULL || x11_display_offset < 0 ||
	    x11_display_offset > UINT16_MAX - X11_BASE_PORT - MAX_DISPLAYS)
		ආපසු -1;

	සඳහා (display_number = x11_display_offset;
	    display_number < x11_display_offset + MAX_DISPLAYS;
	    display_number++) {
		port = X11_BASE_PORT + display_number;
		memset(&hints, 0, parimaa_na(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, parimaa_na strport, "%d", port);
		නම් ((gaierr = getaddrinfo(NULL, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			ආපසු -1;
		}
		සඳහා (ai = aitop; ai; ai = ai->ai_next) {
			නම් (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				continue;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			නම් (sock == -1) {
				නම් ((errno != EINVAL) && (errno != EAFNOSUPPORT)
#ifdef EPFNOSUPPORT
				    && (errno != EPFNOSUPPORT)
#endif 
				    ) {
					error("socket: %.100s", strerror(errno));
					freeaddrinfo(aitop);
					ආපසු -1;
				} නැතහොත් {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					continue;
				}
			}
			නම් (ai->ai_family == AF_INET6)
				sock_set_v6only(sock);
			නම් (x11_use_localhost)
				set_reuseaddr(sock);
			නම් (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", port,
				    strerror(errno));
				close(sock);
				සඳහා (n = 0; n < num_socks; n++)
					close(socks[n]);
				num_socks = 0;
				bha_nga;
			}
			socks[num_socks++] = sock;
			නම් (num_socks == NUM_SOCKS)
				bha_nga;
		}
		freeaddrinfo(aitop);
		නම් (num_socks > 0)
			bha_nga;
	}
	නම් (display_number >= x11_display_offset + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		ආපසු -1;
	}
	/* Start listening for connections on the socket. */
	සඳහා (n = 0; n < num_socks; n++) {
		sock = socks[n];
		නම් (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			ආපසු -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(num_socks + 1, parimaa_na(**chanids));
	සඳහා (n = 0; n < num_socks; n++) {
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
	*display_numberp = display_number;
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
connect_local_xsocket_path(const var_na *pathname)
{
	පූර්ණ_සංඛ්‍යා sock;
	sa_nracanaa sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	නම් (sock == -1) {
		error("socket: %.100s", strerror(errno));
		ආපසු -1;
	}
	memset(&addr, 0, parimaa_na(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, pathname, parimaa_na addr.sun_path);
	නම් (connect(sock, (sa_nracanaa sockaddr *)&addr, parimaa_na(addr)) == 0)
		ආපසු sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_path, strerror(errno));
	ආපසු -1;
}

static පූර්ණ_සංඛ්‍යා
connect_local_xsocket(u_int dnr)
{
	var_na buf[1024];
	snprintf(buf, parimaa_na buf, _PATH_UNIX_X, dnr);
	ආපසු connect_local_xsocket_path(buf);
}

#ifdef __APPLE__
static පූර්ණ_සංඛ්‍යා
is_path_to_xsocket(const var_na *display, var_na *path, size_t pathlen)
{
	sa_nracanaa stat sbuf;

	නම් (strlcpy(path, display, pathlen) >= pathlen) {
		error_f("display path too long");
		ආපසු 0;
	}
	නම් (display[0] != '/')
		ආපසු 0;
	නම් (stat(path, &sbuf) == 0) {
		ආපසු 1;
	} නැතහොත් {
		var_na *dot = strrchr(path, '.');
		නම් (dot != NULL) {
			*dot = '\0';
			නම් (stat(path, &sbuf) == 0) {
				ආපසු 1;
			}
		}
	}
	ආපසු 0;
}
#endif

පූර්ණ_සංඛ්‍යා
x11_connect_display(sa_nracanaa ssh *ssh)
{
	u_int display_number;
	const var_na *display;
	var_na buf[1024], *cp;
	sa_nracanaa addrinfo hints, *ai, *aitop;
	var_na strport[NI_MAXSERV];
	පූර්ණ_සංඛ්‍යා gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	නම් (!display) {
		error("DISPLAY not set.");
		ආපසු -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#ifdef __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		var_na path[PATH_MAX];

		නම් (is_path_to_xsocket(display, path, parimaa_na(path))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_path(path);
			නම් (sock < 0)
				ආපසු -1;

			/* OK, we now have a connection to the display. */
			ආපසු sock;
		}
	}
#endif
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	නම් (strncmp(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		නම් (sscanf(strrchr(display, ':') + 1, "%u",
		    &display_number) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			ආපසු -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_number);
		නම් (sock < 0)
			ආපසු -1;

		/* OK, we now have a connection to the display. */
		ආපසු sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, parimaa_na(buf));
	cp = strchr(buf, ':');
	නම් (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		ආපසු -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	නම් (sscanf(cp + 1, "%u", &display_number) != 1 ||
	    display_number > UINT16_MAX - X11_BASE_PORT) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		ආපසු -1;
	}

	/* Look up the host address */
	memset(&hints, 0, parimaa_na(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, parimaa_na strport, "%u", X11_BASE_PORT + display_number);
	නම් ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		ආපසු -1;
	}
	සඳහා (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		නම් (sock == -1) {
			debug2("socket: %.100s", strerror(errno));
			continue;
		}
		/* Connect it to the display. */
		නම් (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_BASE_PORT + display_number, strerror(errno));
			close(sock);
			continue;
		}
		/* Success */
		bha_nga;
	}
	freeaddrinfo(aitop);
	නම් (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_BASE_PORT + display_number, strerror(errno));
		ආපසු -1;
	}
	set_nodelay(sock);
	ආපසු sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
void
x11_request_forwarding_with_spoofing(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා client_session_id,
    const var_na *disp, const var_na *proto, const var_na *data, පූර්ණ_සංඛ්‍යා want_reply)
{
	sa_nracanaa ssh_channels *sc = ssh->chanctxt;
	u_int data_len = (u_int) strlen(data) / 2;
	u_int i, value;
	const var_na *cp;
	var_na *new_data;
	පූර්ණ_සංඛ්‍යා r, screen_number;

	නම් (sc->x11_saved_display == NULL)
		sc->x11_saved_display = xstrdup(disp);
	නැතහොත් නම් (strcmp(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		ආපසු;
	}

	cp = strchr(disp, ':');
	නම් (cp)
		cp = strchr(cp, '.');
	නම් (cp)
		screen_number = (u_int)strtonum(cp + 1, 0, 400, NULL);
	නැතහොත්
		screen_number = 0;

	නම් (sc->x11_saved_proto == NULL) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_data = xmalloc(data_len);
		සඳහා (i = 0; i < data_len; i++) {
			නම් (sscanf(data + 2 * i, "%2x", &value) != 1) {
				fatal("x11_request_forwarding: bad "
				    "authentication data: %.100s", data);
			}
			sc->x11_saved_data[i] = value;
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
	නම් ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
	    (r = sshpkt_put_cstring(ssh, proto)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, new_data)) != 0 ||
	    (r = sshpkt_put_u32(ssh, screen_number)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send x11-req");
	free(new_data);
}

/*
 * Returns whether an x11 channel was used recently (less than a second ago)
 */
පූර්ණ_සංඛ්‍යා
x11_channel_used_recently(sa_nracanaa ssh *ssh) {
	u_int i;
	Channel *c;
	dviguu_na lastused = 0;

	සඳහා (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		නම් (c == NULL || c->ctype == NULL || c->lastused == 0.0 ||
		    strcmp(c->ctype, "x11-connection") != 0)
			continue;
		නම් (c->lastused > lastused)
			lastused = c->lastused;
	}
	ආපසු lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
