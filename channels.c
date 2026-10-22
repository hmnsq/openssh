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
typedef void chan_fn(struct ssh *, Channel *c);

/*
 * Data structure for storing which hosts are permitted for forward requests.
 * The local sides of any remote forwards are stored in this array to prevent
 * a corrupt remote server from accessing arbitrary TCP/IP ports on our local
 * network (which might be behind a firewall).
 */
/* XXX: streamlocal wants a path instead of host:port */
/*      Overload host_to_connect; we could just make this match Forward */
/*	XXX - can we use listen_host instead of listen_path? */
struct permission {
	char *host_to_connect;		/* Connect to 'host'. */
	số_nguyên port_to_connect;		/* Connect to 'port'. */
	char *listen_host;		/* Remote side should listen address. */
	char *listen_path;		/* Remote side should listen path. */
	số_nguyên listen_port;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

/* Context for non-blocking connects */
struct channel_connect {
	char *host;
	số_nguyên port;
	struct addrinfo *ai, *aitop;
};

/*
 * Stores the forwarding permission state for a single direction (local or
 * remote).
 */
struct permission_set {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int num_permitted_user;
	struct permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int num_permitted_admin;
	struct permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	số_nguyên all_permitted;
};

/* Used to record timeouts per channel type */
struct ssh_channel_timeout {
	char *type_pattern;
	double timeout_secs;
};

/* Master structure for channels state */
struct ssh_channels {
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
	struct permission_set local_perms;
	struct permission_set remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	char *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	char *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	char *x11_saved_data;
	u_int x11_saved_data_len;

	/* Deadline after which all X11 connections are refused */
	double x11_refuse_time;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_data;
	u_int x11_fake_data_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	số_nguyên IPv4or6;

	/* Set SO_KEEPALIVE on TCP connections */
	số_nguyên want_tcp_keepalive;

	/* Channel timeouts by type */
	struct ssh_channel_timeout *timeouts;
	size_t ntimeouts;
	/* Global timeout for all OPEN channels */
	double global_deadline;
	double lastused;
	/* pattern-lists used to classify channels as bulk */
	char *bulk_classifier_tty, *bulk_classifier_notty;
	/* Number of active bulk channels (set by channel_handler) */
	u_int nbulk;
};

/* helper */
static void port_open_helper(struct ssh *ssh, Channel *c, char *rtype);
static const char *channel_rfwd_bind_host(const char *listen_host);

/* non-blocking connect helpers */
static số_nguyên connect_next(struct ssh *, struct channel_connect *);
static Channel *rdynamic_connect_prepare(struct ssh *, char *, char *);
static số_nguyên rdynamic_connect_finish(struct ssh *, Channel *);

/* Setup helper */
static void channel_handler_init(struct ssh_channels *sc);

/* -- channel core */

void
channel_init_channels(struct ssh *ssh)
{
	struct ssh_channels *sc;

	nếu ((sc = calloc(1, sizeof(*sc))) == NULL)
		fatal_f("allocation failed");
	sc->channels_alloc = 10;
	sc->channels = xcalloc(sc->channels_alloc, sizeof(*sc->channels));
	sc->IPv4or6 = AF_UNSPEC;
	sc->bulk_classifier_tty = xstrdup(CHANNEL_BULK_TTY);
	sc->bulk_classifier_notty = xstrdup(CHANNEL_BULK_NOTTY);
	channel_handler_init(sc);

	ssh->chanctxt = sc;
}

Channel *
channel_by_id(struct ssh *ssh, số_nguyên id)
{
	Channel *c;

	nếu (id < 0 || (u_int)id >= ssh->chanctxt->channels_alloc) {
		logit_f("%d: bad id", id);
		trả_về NULL;
	}
	c = ssh->chanctxt->channels[id];
	nếu (c == NULL) {
		logit_f("%d: bad id: channel free", id);
		trả_về NULL;
	}
	trả_về c;
}

Channel *
channel_by_remote_id(struct ssh *ssh, u_int remote_id)
{
	Channel *c;
	u_int i;

	cho (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		nếu (c != NULL && c->have_remote_id && c->remote_id == remote_id)
			trả_về c;
	}
	trả_về NULL;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private channels, like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(struct ssh *ssh, số_nguyên id)
{
	Channel *c;

	nếu ((c = channel_by_id(ssh, id)) == NULL)
		trả_về NULL;

	switch (c->type) {
	case SSH_CHANNEL_X11_OPEN:
	case SSH_CHANNEL_LARVAL:
	case SSH_CHANNEL_CONNECTING:
	case SSH_CHANNEL_DYNAMIC:
	case SSH_CHANNEL_RDYNAMIC_OPEN:
	case SSH_CHANNEL_RDYNAMIC_FINISH:
	case SSH_CHANNEL_OPENING:
	case SSH_CHANNEL_OPEN:
	case SSH_CHANNEL_ABANDONED:
	case SSH_CHANNEL_MUX_PROXY:
		trả_về c;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	trả_về NULL;
}

static void
free_connect_ctx(struct channel_connect *cctx)
{
	free(cctx->host);
	nếu (cctx->aitop) {
		nếu (cctx->aitop->ai_family == AF_UNIX)
			free(cctx->aitop);
		không_thì
			freeaddrinfo(cctx->aitop);
	}
	memset(cctx, 0, sizeof(*cctx));
}

static void
channel_free_connect_ctx(Channel *c)
{
	nếu (c == NULL || c->connect_ctx == NULL)
		trả_về;
	free_connect_ctx(c->connect_ctx);
	free(c->connect_ctx);
	c->connect_ctx = NULL;
}

/* Enable/disable TCP keepalives for X11 and port-forwarding sockets */
void
channel_set_tcp_keepalives(struct ssh *ssh, số_nguyên on)
{
	ssh->chanctxt->want_tcp_keepalive = on;
}

/*
 * Add a timeout for open channels whose c->ctype (or c->xctype if it is set)
 * match type_pattern.
 */
void
channel_add_timeout(struct ssh *ssh, const char *type_pattern,
    double timeout_secs)
{
	struct ssh_channels *sc = ssh->chanctxt;

	nếu (strcmp(type_pattern, "global") == 0) {
		debug2_f("global channel timeout %f seconds", timeout_secs);
		sc->global_deadline = timeout_secs;
		trả_về;
	}
	debug2_f("channel type \"%s\" timeout %f seconds",
	    type_pattern, timeout_secs);
	sc->timeouts = xrecallocarray(sc->timeouts, sc->ntimeouts,
	    sc->ntimeouts + 1, sizeof(*sc->timeouts));
	sc->timeouts[sc->ntimeouts].type_pattern = xstrdup(type_pattern);
	sc->timeouts[sc->ntimeouts].timeout_secs = timeout_secs;
	sc->ntimeouts++;
}

/* Clears all previously-added channel timeouts */
void
channel_clear_timeouts(struct ssh *ssh)
{
	struct ssh_channels *sc = ssh->chanctxt;
	size_t i;

	debug3_f("clearing");
	cho (i = 0; i < sc->ntimeouts; i++)
		free(sc->timeouts[i].type_pattern);
	free(sc->timeouts);
	sc->timeouts = NULL;
	sc->ntimeouts = 0;
}

static double
lookup_timeout(struct ssh *ssh, const char *type)
{
	struct ssh_channels *sc = ssh->chanctxt;
	size_t i;

	cho (i = 0; i < sc->ntimeouts; i++) {
		nếu (match_pattern(type, sc->timeouts[i].type_pattern))
			trả_về sc->timeouts[i].timeout_secs;
	}

	trả_về 0;
}

static void
channel_classify(struct ssh *ssh, Channel *c)
{
	struct ssh_channels *sc = ssh->chanctxt;
	const char *type = c->xctype == NULL ? c->ctype : c->xctype;
	const số_nguyên has_tty = c->isatty || c->remote_has_tty;
	const char *classifier = has_tty ?
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
channel_set_xtype(struct ssh *ssh, số_nguyên id, const char *xctype)
{
	struct ssh_channels *sc = ssh->chanctxt;
	Channel *c;

	nếu ((c = channel_by_id(ssh, id)) == NULL)
		fatal_f("missing channel %d", id);
	nếu (c->xctype != NULL)
		free(c->xctype);
	c->xctype = xstrdup(xctype);
	/* Only override deadline if xctype has a more specific match. */
	double xtype_deadline = lookup_timeout(ssh, c->xctype);
	nếu (xtype_deadline != 0)
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
channel_set_used_time(struct ssh *ssh, Channel *c)
{
	ssh->chanctxt->lastused = monotime_double();
	nếu (c != NULL)
		c->lastused = ssh->chanctxt->lastused;
}

/*
 * Get the time at which a channel is due to time out for inactivity.
 * Returns 0 if the channel is not due to time out ever.
 */
static double
channel_get_expiry(struct ssh *ssh, Channel *c)
{
	struct ssh_channels *sc = ssh->chanctxt;
	double expiry = 0, channel_expiry;

	nếu (sc->lastused != 0 && sc->global_deadline != 0)
		expiry = sc->lastused + sc->global_deadline;
	nếu (c->lastused != 0 && c->inactive_deadline != 0) {
		channel_expiry = c->lastused + c->inactive_deadline;
		nếu (expiry == 0 || channel_expiry < expiry)
			expiry = channel_expiry;
	}
	trả_về expiry;
}

/* Returns non-zero if there is an open, non-interactive channel */
số_nguyên
channel_has_bulk(struct ssh *ssh)
{
	trả_về ssh->chanctxt != NULL && ssh->chanctxt->nbulk != 0;
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */
static void
channel_register_fds(struct ssh *ssh, Channel *c, số_nguyên rfd, số_nguyên wfd, số_nguyên efd,
    số_nguyên extusage, số_nguyên nonblock, số_nguyên is_tty)
{
	số_nguyên val;

	nếu (rfd != -1)
		(void)fcntl(rfd, F_SETFD, FD_CLOEXEC);
	nếu (wfd != -1 && wfd != rfd)
		(void)fcntl(wfd, F_SETFD, FD_CLOEXEC);
	nếu (efd != -1 && efd != rfd && efd != wfd)
		(void)fcntl(efd, F_SETFD, FD_CLOEXEC);

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->efd = efd;
	c->extended_usage = extusage;

	nếu ((c->isatty = is_tty) != 0)
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	c->wfd_isatty = is_tty || isatty(c->wfd);
#endif

	/* enable nonblocking mode */
	c->restore_block = 0;
	nếu (nonblock == CHANNEL_NONBLOCK_STDIO) {
		/*
		 * Special handling for stdio file descriptors: do not set
		 * non-blocking mode if they are TTYs. Otherwise prepare to
		 * restore their blocking state on exit to avoid interfering
		 * with other programs that follow.
		 */
		nếu (rfd != -1 && !isatty(rfd) &&
		    (val = fcntl(rfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[0] = val;
			c->restore_block |= CHANNEL_RESTORE_RFD;
			set_nonblock(rfd);
		}
		nếu (wfd != -1 && !isatty(wfd) &&
		    (val = fcntl(wfd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[1] = val;
			c->restore_block |= CHANNEL_RESTORE_WFD;
			set_nonblock(wfd);
		}
		nếu (efd != -1 && !isatty(efd) &&
		    (val = fcntl(efd, F_GETFL)) != -1 && !(val & O_NONBLOCK)) {
			c->restore_flags[2] = val;
			c->restore_block |= CHANNEL_RESTORE_EFD;
			set_nonblock(efd);
		}
	} không_thì nếu (nonblock) {
		nếu (rfd != -1)
			set_nonblock(rfd);
		nếu (wfd != -1)
			set_nonblock(wfd);
		nếu (efd != -1)
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
channel_new(struct ssh *ssh, char *ctype, số_nguyên type, số_nguyên rfd, số_nguyên wfd, số_nguyên efd,
    u_int window, u_int maxpack, số_nguyên extusage, const char *remote_name,
    số_nguyên nonblock)
{
	struct ssh_channels *sc = ssh->chanctxt;
	u_int i, found = 0;
	Channel *c;
	số_nguyên r;

	/* Try to find a free slot where to put the new channel. */
	cho (i = 0; i < sc->channels_alloc; i++) {
		nếu (sc->channels[i] == NULL) {
			/* Found a free slot. */
			found = i;
			break;
		}
	}
	nếu (i >= sc->channels_alloc) {
		/*
		 * There are no free slots. Take last+1 slot and expand
		 * the array.
		 */
		found = sc->channels_alloc;
		nếu (sc->channels_alloc > CHANNELS_MAX_CHANNELS)
			fatal_f("internal error: channels_alloc %d too big",
			    sc->channels_alloc);
		sc->channels = xrecallocarray(sc->channels, sc->channels_alloc,
		    sc->channels_alloc + 10, sizeof(*sc->channels));
		sc->channels_alloc += 10;
		debug2("channel: expanding %d", sc->channels_alloc);
	}
	/* Initialize and return new channel. */
	c = sc->channels[found] = xcalloc(1, sizeof(Channel));
	nếu ((c->input = sshbuf_new()) == NULL ||
	    (c->output = sshbuf_new()) == NULL ||
	    (c->extended = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	nếu ((r = sshbuf_set_max_size(c->input, CHAN_INPUT_MAX)) != 0)
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
	trả_về c;
}

void
channel_set_tty(struct ssh *ssh, Channel *c)
{
	c->remote_has_tty = 1;
	channel_classify(ssh, c);
}

số_nguyên
channel_close_fd(struct ssh *ssh, Channel *c, số_nguyên *fdp)
{
	số_nguyên ret, fd = *fdp;

	nếu (fd == -1)
		trả_về 0;

	/* restore blocking */
	nếu (*fdp == c->rfd &&
	    (c->restore_block & CHANNEL_RESTORE_RFD) != 0)
		(void)fcntl(*fdp, F_SETFL, c->restore_flags[0]);
	không_thì nếu (*fdp == c->wfd &&
	    (c->restore_block & CHANNEL_RESTORE_WFD) != 0)
		(void)fcntl(*fdp, F_SETFL, c->restore_flags[1]);
	không_thì nếu (*fdp == c->efd &&
	    (c->restore_block & CHANNEL_RESTORE_EFD) != 0)
		(void)fcntl(*fdp, F_SETFL, c->restore_flags[2]);

	nếu (*fdp == c->rfd) {
		c->io_want &= ~SSH_CHAN_IO_RFD;
		c->io_ready &= ~SSH_CHAN_IO_RFD;
		c->rfd = -1;
		c->pfds[0] = -1;
	}
	nếu (*fdp == c->wfd) {
		c->io_want &= ~SSH_CHAN_IO_WFD;
		c->io_ready &= ~SSH_CHAN_IO_WFD;
		c->wfd = -1;
		c->pfds[1] = -1;
	}
	nếu (*fdp == c->efd) {
		c->io_want &= ~SSH_CHAN_IO_EFD;
		c->io_ready &= ~SSH_CHAN_IO_EFD;
		c->efd = -1;
		c->pfds[2] = -1;
	}
	nếu (*fdp == c->sock) {
		c->io_want &= ~SSH_CHAN_IO_SOCK;
		c->io_ready &= ~SSH_CHAN_IO_SOCK;
		c->sock = -1;
		c->pfds[3] = -1;
	}

	ret = close(fd);
	*fdp = -1; /* probably redundant */
	trả_về ret;
}

/* Close all channel fd/socket. */
static void
channel_close_fds(struct ssh *ssh, Channel *c)
{
	số_nguyên sock = c->sock, rfd = c->rfd, wfd = c->wfd, efd = c->efd;

	channel_close_fd(ssh, c, &c->sock);
	nếu (rfd != sock)
		channel_close_fd(ssh, c, &c->rfd);
	nếu (wfd != sock && wfd != rfd)
		channel_close_fd(ssh, c, &c->wfd);
	nếu (efd != sock && efd != rfd && efd != wfd)
		channel_close_fd(ssh, c, &c->efd);
}

static void
fwd_perm_clear(struct permission *perm)
{
	free(perm->host_to_connect);
	free(perm->listen_host);
	free(perm->listen_path);
	memset(perm, 0, sizeof(*perm));
}

/* Returns an printable name for the specified forwarding permission list */
static const char *
fwd_ident(số_nguyên who, số_nguyên where)
{
	nếu (who == FORWARD_ADM) {
		nếu (where == FORWARD_LOCAL)
			trả_về "admin local";
		không_thì nếu (where == FORWARD_REMOTE)
			trả_về "admin remote";
	} không_thì nếu (who == FORWARD_USER) {
		nếu (where == FORWARD_LOCAL)
			trả_về "user local";
		không_thì nếu (where == FORWARD_REMOTE)
			trả_về "user remote";
	}
	fatal("Unknown forward permission list %d/%d", who, where);
}

/* Returns the forwarding permission list for the specified direction */
static struct permission_set *
permission_set_get(struct ssh *ssh, số_nguyên where)
{
	struct ssh_channels *sc = ssh->chanctxt;

	switch (where) {
	case FORWARD_LOCAL:
		trả_về &sc->local_perms;
		break;
	case FORWARD_REMOTE:
		trả_về &sc->remote_perms;
		break;
	default:
		fatal_f("invalid forwarding direction %d", where);
	}
}

/* Returns pointers to the specified forwarding list and its element count */
static void
permission_set_get_array(struct ssh *ssh, số_nguyên who, số_nguyên where,
    struct permission ***permpp, u_int **npermpp)
{
	struct permission_set *pset = permission_set_get(ssh, where);

	switch (who) {
	case FORWARD_USER:
		*permpp = &pset->permitted_user;
		*npermpp = &pset->num_permitted_user;
		break;
	case FORWARD_ADM:
		*permpp = &pset->permitted_admin;
		*npermpp = &pset->num_permitted_admin;
		break;
	default:
		fatal_f("invalid forwarding client %d", who);
	}
}

/* Adds an entry to the specified forwarding list */
static số_nguyên
permission_set_add(struct ssh *ssh, số_nguyên who, số_nguyên where,
    const char *host_to_connect, số_nguyên port_to_connect,
    const char *listen_host, const char *listen_path, số_nguyên listen_port,
    Channel *downstream)
{
	struct permission **permp;
	u_int n, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);

	nếu (*npermp >= INT_MAX)
		fatal_f("%s overflow", fwd_ident(who, where));

	*permp = xrecallocarray(*permp, *npermp, *npermp + 1, sizeof(**permp));
	n = (*npermp)++;
#define MAYBE_DUP(s) ((s == NULL) ? NULL : xstrdup(s))
	(*permp)[n].host_to_connect = MAYBE_DUP(host_to_connect);
	(*permp)[n].port_to_connect = port_to_connect;
	(*permp)[n].listen_host = MAYBE_DUP(listen_host);
	(*permp)[n].listen_path = MAYBE_DUP(listen_path);
	(*permp)[n].listen_port = listen_port;
	(*permp)[n].downstream = downstream;
#undef MAYBE_DUP
	trả_về (số_nguyên)n;
}

static void
mux_remove_remote_forwardings(struct ssh *ssh, Channel *c)
{
	struct ssh_channels *sc = ssh->chanctxt;
	struct permission_set *pset = &sc->local_perms;
	struct permission *perm;
	số_nguyên r;
	u_int i;

	cho (i = 0; i < pset->num_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		nếu (perm->downstream != c)
			continue;

		/* cancel on the server, since mux client is gone */
		debug("channel %d: cleanup remote forward for %s:%u",
		    c->self, perm->listen_host, perm->listen_port);
		nếu ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
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
channel_free(struct ssh *ssh, Channel *c)
{
	struct ssh_channels *sc = ssh->chanctxt;
	char *s;
	u_int i, n;
	Channel *other;
	struct channel_confirm *cc;

	cho (n = 0, i = 0; i < sc->channels_alloc; i++) {
		nếu ((other = sc->channels[i]) == NULL)
			continue;
		n++;
		/* detach from mux client and prepare for closing */
		nếu (c->type == SSH_CHANNEL_MUX_CLIENT &&
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

	nếu (c->type == SSH_CHANNEL_MUX_CLIENT) {
		mux_remove_remote_forwardings(ssh, c);
		free(c->mux_ctx);
		c->mux_ctx = NULL;
	} không_thì nếu (c->type == SSH_CHANNEL_MUX_LISTENER) {
		free(c->mux_ctx);
		c->mux_ctx = NULL;
	}

	nếu (log_level_get() >= SYSLOG_LEVEL_DEBUG3) {
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
	trong_khi ((cc = TAILQ_FIRST(&c->status_confirms)) != NULL) {
		nếu (cc->abandon_cb != NULL)
			cc->abandon_cb(ssh, c, cc->ctx);
		TAILQ_REMOVE(&c->status_confirms, cc, entry);
		freezero(cc, sizeof(*cc));
	}
	nếu (c->filter_cleanup != NULL && c->filter_ctx != NULL)
		c->filter_cleanup(ssh, c->self, c->filter_ctx);
	sc->channels[c->self] = NULL;
	freezero(c, sizeof(*c));
}

void
channel_free_all(struct ssh *ssh)
{
	u_int i;
	struct ssh_channels *sc = ssh->chanctxt;

	cho (i = 0; i < sc->channels_alloc; i++)
		nếu (sc->channels[i] != NULL)
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
channel_free_channels(struct ssh *ssh)
{
	struct ssh_channels *sc;

	nếu (ssh == NULL || ssh->chanctxt == NULL)
		trả_về;
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
	freezero(sc, sizeof(*sc));
	ssh->chanctxt = NULL;
}

/*
 * Closes the sockets/fds of all channels.  This is used to close extra file
 * descriptors after a fork.
 */
void
channel_close_all(struct ssh *ssh)
{
	u_int i;

	cho (i = 0; i < ssh->chanctxt->channels_alloc; i++)
		nếu (ssh->chanctxt->channels[i] != NULL)
			channel_close_fds(ssh, ssh->chanctxt->channels[i]);
}

/*
 * Stop listening to channels.
 */
void
channel_stop_listening(struct ssh *ssh)
{
	u_int i;
	Channel *c;

	cho (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		nếu (c != NULL) {
			switch (c->type) {
			case SSH_CHANNEL_AUTH_SOCKET:
			case SSH_CHANNEL_PORT_LISTENER:
			case SSH_CHANNEL_RPORT_LISTENER:
			case SSH_CHANNEL_X11_LISTENER:
			case SSH_CHANNEL_UNIX_LISTENER:
			case SSH_CHANNEL_RUNIX_LISTENER:
				channel_close_fd(ssh, c, &c->sock);
				channel_free(ssh, c);
				break;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */
số_nguyên
channel_not_very_much_buffered_data(struct ssh *ssh)
{
	u_int i;
	u_int maxsize = ssh_packet_get_maxsize(ssh);
	Channel *c;

	cho (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		nếu (c == NULL || c->type != SSH_CHANNEL_OPEN)
			continue;
		nếu (sshbuf_len(c->output) > maxsize) {
			debug2("channel %d: big output buffer %zu > %u",
			    c->self, sshbuf_len(c->output), maxsize);
			trả_về 0;
		}
	}
	trả_về 1;
}

/* Returns true if any channel is still open. */
số_nguyên
channel_still_open(struct ssh *ssh)
{
	u_int i;
	Channel *c;

	cho (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		nếu (c == NULL)
			continue;
		switch (c->type) {
		case SSH_CHANNEL_X11_LISTENER:
		case SSH_CHANNEL_PORT_LISTENER:
		case SSH_CHANNEL_RPORT_LISTENER:
		case SSH_CHANNEL_MUX_LISTENER:
		case SSH_CHANNEL_CLOSED:
		case SSH_CHANNEL_AUTH_SOCKET:
		case SSH_CHANNEL_DYNAMIC:
		case SSH_CHANNEL_RDYNAMIC_OPEN:
		case SSH_CHANNEL_CONNECTING:
		case SSH_CHANNEL_ZOMBIE:
		case SSH_CHANNEL_ABANDONED:
		case SSH_CHANNEL_UNIX_LISTENER:
		case SSH_CHANNEL_RUNIX_LISTENER:
			continue;
		case SSH_CHANNEL_LARVAL:
			continue;
		case SSH_CHANNEL_OPENING:
		case SSH_CHANNEL_OPEN:
		case SSH_CHANNEL_RDYNAMIC_FINISH:
		case SSH_CHANNEL_X11_OPEN:
		case SSH_CHANNEL_MUX_CLIENT:
		case SSH_CHANNEL_MUX_PROXY:
			trả_về 1;
		default:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	trả_về 0;
}

/* Returns true if a channel with a TTY is open. */
số_nguyên
channel_tty_open(struct ssh *ssh)
{
	u_int i;
	Channel *c;

	cho (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		nếu (c == NULL || c->type != SSH_CHANNEL_OPEN)
			continue;
		nếu (c->client_tty)
			trả_về 1;
	}
	trả_về 0;
}

/* Returns the id of an open channel suitable for keepaliving */
số_nguyên
channel_find_open(struct ssh *ssh)
{
	u_int i;
	Channel *c;

	cho (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		nếu (c == NULL || !c->have_remote_id)
			continue;
		switch (c->type) {
		case SSH_CHANNEL_CLOSED:
		case SSH_CHANNEL_DYNAMIC:
		case SSH_CHANNEL_RDYNAMIC_OPEN:
		case SSH_CHANNEL_RDYNAMIC_FINISH:
		case SSH_CHANNEL_X11_LISTENER:
		case SSH_CHANNEL_PORT_LISTENER:
		case SSH_CHANNEL_RPORT_LISTENER:
		case SSH_CHANNEL_MUX_LISTENER:
		case SSH_CHANNEL_MUX_CLIENT:
		case SSH_CHANNEL_MUX_PROXY:
		case SSH_CHANNEL_OPENING:
		case SSH_CHANNEL_CONNECTING:
		case SSH_CHANNEL_ZOMBIE:
		case SSH_CHANNEL_ABANDONED:
		case SSH_CHANNEL_UNIX_LISTENER:
		case SSH_CHANNEL_RUNIX_LISTENER:
			continue;
		case SSH_CHANNEL_LARVAL:
		case SSH_CHANNEL_AUTH_SOCKET:
		case SSH_CHANNEL_OPEN:
		case SSH_CHANNEL_X11_OPEN:
			trả_về i;
		default:
			fatal_f("bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	trả_về -1;
}

/* Returns the state of the channel's extended usage flag */
const char *
channel_format_extended_usage(const Channel *c)
{
	nếu (c->efd == -1)
		trả_về "closed";

	switch (c->extended_usage) {
	case CHAN_EXTENDED_WRITE:
		trả_về "write";
	case CHAN_EXTENDED_READ:
		trả_về "read";
	case CHAN_EXTENDED_IGNORE:
		trả_về "ignore";
	default:
		trả_về "UNKNOWN";
	}
}

static char *
channel_format_status(const Channel *c)
{
	char *ret = NULL;

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
	trả_về ret;
}

/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */
char *
channel_open_message(struct ssh *ssh)
{
	struct sshbuf *buf;
	Channel *c;
	u_int i;
	số_nguyên r;
	char *cp, *ret;

	nếu ((buf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	nếu ((r = sshbuf_putf(buf,
	    "The following connections are open:\r\n")) != 0)
		fatal_fr(r, "sshbuf_putf");
	cho (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		nếu (c == NULL)
			continue;
		switch (c->type) {
		case SSH_CHANNEL_X11_LISTENER:
		case SSH_CHANNEL_PORT_LISTENER:
		case SSH_CHANNEL_RPORT_LISTENER:
		case SSH_CHANNEL_CLOSED:
		case SSH_CHANNEL_AUTH_SOCKET:
		case SSH_CHANNEL_ZOMBIE:
		case SSH_CHANNEL_ABANDONED:
		case SSH_CHANNEL_MUX_LISTENER:
		case SSH_CHANNEL_UNIX_LISTENER:
		case SSH_CHANNEL_RUNIX_LISTENER:
			continue;
		case SSH_CHANNEL_LARVAL:
		case SSH_CHANNEL_OPENING:
		case SSH_CHANNEL_CONNECTING:
		case SSH_CHANNEL_DYNAMIC:
		case SSH_CHANNEL_RDYNAMIC_OPEN:
		case SSH_CHANNEL_RDYNAMIC_FINISH:
		case SSH_CHANNEL_OPEN:
		case SSH_CHANNEL_X11_OPEN:
		case SSH_CHANNEL_MUX_PROXY:
		case SSH_CHANNEL_MUX_CLIENT:
			cp = channel_format_status(c);
			nếu ((r = sshbuf_putf(buf, "  #%d %.300s (%s)\r\n",
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
	nếu ((ret = sshbuf_dup_string(buf)) == NULL)
		fatal_f("sshbuf_dup_string");
	sshbuf_free(buf);
	trả_về ret;
}

void
channel_report_open(struct ssh *ssh, số_nguyên level)
{
	char *open, *oopen, *cp, ident[256];

	sshpkt_fmt_connection_id(ssh, ident, sizeof(ident));
	do_log2(level, "Connection: %s (pid %ld)", ident, (long)getpid());
	open = oopen = channel_open_message(ssh);
	trong_khi ((cp = strsep(&open, "\r\n")) != NULL) {
		nếu (*cp != '\0')
			do_log2(level, "%s", cp);
	}
	free(oopen);
}

static void
open_preamble(struct ssh *ssh, const char *where, Channel *c, const char *type)
{
	số_nguyên r;

	nếu ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, type)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0) {
		fatal_r(r, "%s: channel %i: open", where, c->self);
	}
}

void
channel_send_open(struct ssh *ssh, số_nguyên id)
{
	Channel *c = channel_lookup(ssh, id);
	số_nguyên r;

	nếu (c == NULL) {
		logit("channel_send_open: %d: bad id", id);
		trả_về;
	}
	debug2("channel %d: send open", id);
	open_preamble(ssh, __func__, c, c->ctype);
	nếu ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

void
channel_request_start(struct ssh *ssh, số_nguyên id, const char *service,
    số_nguyên wantconfirm)
{
	Channel *c = channel_lookup(ssh, id);
	số_nguyên r;

	nếu (c == NULL) {
		logit_f("%d: unknown channel id", id);
		trả_về;
	}
	nếu (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	nếu ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_put_u8(ssh, wantconfirm)) != 0) {
		fatal_fr(r, "channel %i", c->self);
	}
}

void
channel_register_status_confirm(struct ssh *ssh, số_nguyên id,
    channel_confirm_cb *cb, channel_confirm_abandon_cb *abandon_cb, void *ctx)
{
	struct channel_confirm *cc;
	Channel *c;

	nếu ((c = channel_lookup(ssh, id)) == NULL)
		fatal_f("%d: bad id", id);

	cc = xcalloc(1, sizeof(*cc));
	cc->cb = cb;
	cc->abandon_cb = abandon_cb;
	cc->ctx = ctx;
	TAILQ_INSERT_TAIL(&c->status_confirms, cc, entry);
}

void
channel_register_open_confirm(struct ssh *ssh, số_nguyên id,
    channel_open_fn *fn, void *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	nếu (c == NULL) {
		logit_f("%d: bad id", id);
		trả_về;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}

void
channel_register_cleanup(struct ssh *ssh, số_nguyên id,
    channel_callback_fn *fn, số_nguyên do_close)
{
	Channel *c = channel_by_id(ssh, id);

	nếu (c == NULL) {
		logit_f("%d: bad id", id);
		trả_về;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}

void
channel_cancel_cleanup(struct ssh *ssh, số_nguyên id)
{
	Channel *c = channel_by_id(ssh, id);

	nếu (c == NULL) {
		logit_f("%d: bad id", id);
		trả_về;
	}
	c->detach_user = NULL;
	c->detach_close = 0;
}

void
channel_register_filter(struct ssh *ssh, số_nguyên id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, void *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	nếu (c == NULL) {
		logit_f("%d: bad id", id);
		trả_về;
	}
	c->input_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}

void
channel_set_fds(struct ssh *ssh, số_nguyên id, số_nguyên rfd, số_nguyên wfd, số_nguyên efd,
    số_nguyên extusage, số_nguyên nonblock, số_nguyên is_tty, u_int window_max)
{
	Channel *c = channel_lookup(ssh, id);
	số_nguyên r;

	nếu (c == NULL || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	nếu (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	channel_register_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
	c->type = SSH_CHANNEL_OPEN;
	channel_set_used_time(ssh, c);
	c->local_window = c->local_window_max = window_max;

	nếu ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_WINDOW_ADJUST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

static void
channel_pre_listener(struct ssh *ssh, Channel *c)
{
	c->io_want = SSH_CHAN_IO_SOCK_R;
}

static void
channel_pre_connecting(struct ssh *ssh, Channel *c)
{
	debug3("channel %d: waiting for connection", c->self);
	c->io_want = SSH_CHAN_IO_SOCK_W;
}

static void
channel_pre_open(struct ssh *ssh, Channel *c)
{
	c->io_want = 0;
	nếu (c->istate == CHAN_INPUT_OPEN &&
	    c->remote_window > 0 &&
	    sshbuf_len(c->input) < c->remote_window &&
	    sshbuf_check_reserve(c->input, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	nếu (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		nếu (sshbuf_len(c->output) > 0) {
			c->io_want |= SSH_CHAN_IO_WFD;
		} không_thì nếu (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			nếu (CHANNEL_EFD_OUTPUT_ACTIVE(c))
				debug2("channel %d: "
				    "obuf_empty delayed efd %d/(%zu)", c->self,
				    c->efd, sshbuf_len(c->extended));
			không_thì
				chan_obuf_empty(ssh, c);
		}
	}
	/** XXX check close conditions, too */
	nếu (c->efd != -1 && !(c->istate == CHAN_INPUT_CLOSED &&
	    c->ostate == CHAN_OUTPUT_CLOSED)) {
		nếu (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    sshbuf_len(c->extended) > 0)
			c->io_want |= SSH_CHAN_IO_EFD_W;
		không_thì nếu (c->efd != -1 && !(c->flags & CHAN_EOF_SENT) &&
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
static số_nguyên
x11_open_helper(struct ssh *ssh, struct sshbuf *b)
{
	struct ssh_channels *sc = ssh->chanctxt;
	u_char *ucp;
	u_int proto_len, data_len;

	nếu (sc->x11_saved_proto == NULL) {
		error("X11 forwarding opened before X11 forwarding requested");
		trả_về -1;
	}

	/* Is this being called after the refusal deadline? */
	nếu (sc->x11_refuse_time != 0.0 &&
	    monotime_double() >= sc->x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		trả_về -1;
	}

	/* Check if the fixed size part of the packet is in buffer. */
	nếu (sshbuf_len(b) < 12)
		trả_về 0;

	/* Parse the lengths of variable-length fields. */
	ucp = sshbuf_mutable_ptr(b);
	nếu (ucp[0] == 0x42) {	/* Byte order MSB first. */
		proto_len = 256 * ucp[6] + ucp[7];
		data_len = 256 * ucp[8] + ucp[9];
	} không_thì nếu (ucp[0] == 0x6c) {	/* Byte order LSB first. */
		proto_len = ucp[6] + 256 * ucp[7];
		data_len = ucp[8] + 256 * ucp[9];
	} không_thì {
		debug2("Initial X11 packet contains bad byte order byte: 0x%x",
		    ucp[0]);
		trả_về -1;
	}

	/* Check if the whole packet is in buffer. */
	nếu (sshbuf_len(b) <
	    12 + ((proto_len + 3) & ~3) + ((data_len + 3) & ~3))
		trả_về 0;

	/* Check if authentication protocol matches. */
	nếu (proto_len != strlen(sc->x11_saved_proto) ||
	    memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
		debug2("X11 connection uses different authentication protocol.");
		trả_về -1;
	}
	/* Check if authentication data matches our fake data. */
	nếu (data_len != sc->x11_fake_data_len ||
	    timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
		sc->x11_fake_data, sc->x11_fake_data_len) != 0) {
		debug2("X11 auth data does not match fake data.");
		trả_về -1;
	}
	/* Check fake data length */
	nếu (sc->x11_fake_data_len != sc->x11_saved_data_len) {
		error("X11 fake_data_len %d != saved_data_len %d",
		    sc->x11_fake_data_len, sc->x11_saved_data_len);
		trả_về -1;
	}
	/*
	 * Received authentication protocol and data match
	 * our fake data. Substitute the fake data with real
	 * data.
	 */
	memcpy(ucp + 12 + ((proto_len + 3) & ~3),
	    sc->x11_saved_data, sc->x11_saved_data_len);
	trả_về 1;
}

void
channel_force_close(struct ssh *ssh, Channel *c, số_nguyên abandon)
{
	debug3_f("channel %d: forcibly closing", c->self);
	nếu (c->istate == CHAN_INPUT_OPEN)
		chan_read_failed(ssh, c);
	nếu (c->istate == CHAN_INPUT_WAIT_DRAIN) {
		sshbuf_reset(c->input);
		chan_ibuf_empty(ssh, c);
	}
	nếu (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		sshbuf_reset(c->output);
		chan_write_failed(ssh, c);
	}
	nếu (c->detach_user)
		c->detach_user(ssh, c->self, 1, NULL);
	nếu (c->efd != -1)
		channel_close_fd(ssh, c, &c->efd);
	nếu (abandon)
		c->type = SSH_CHANNEL_ABANDONED;
	/* exempt from inactivity timeouts */
	c->inactive_deadline = 0;
	c->lastused = 0;
}

static void
channel_pre_x11_open(struct ssh *ssh, Channel *c)
{
	số_nguyên ret = x11_open_helper(ssh, c->output);

	/* c->force_drain = 1; */

	nếu (ret == 1) {
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		channel_pre_open(ssh, c);
	} không_thì nếu (ret == -1) {
		logit("X11 connection rejected because of wrong "
		    "authentication.");
		debug2("X11 rejected %d i%d/o%d",
		    c->self, c->istate, c->ostate);
		channel_force_close(ssh, c, 0);
	}
}

static void
channel_pre_mux_client(struct ssh *ssh, Channel *c)
{
	c->io_want = 0;
	nếu (c->istate == CHAN_INPUT_OPEN && !c->mux_pause &&
	    sshbuf_check_reserve(c->input, CHAN_RBUF) == 0)
		c->io_want |= SSH_CHAN_IO_RFD;
	nếu (c->istate == CHAN_INPUT_WAIT_DRAIN) {
		/* clear buffer immediately (discard any partial packet) */
		sshbuf_reset(c->input);
		chan_ibuf_empty(ssh, c);
		/* Start output drain. XXX just kill chan? */
		chan_rcvd_oclose(ssh, c);
	}
	nếu (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		nếu (sshbuf_len(c->output) > 0)
			c->io_want |= SSH_CHAN_IO_WFD;
		không_thì nếu (c->ostate == CHAN_OUTPUT_WAIT_DRAIN)
			chan_obuf_empty(ssh, c);
	}
}

static inline số_nguyên
socks_decode_error(Channel *c, số_nguyên status, const char *func, const char *msg)
{
	nếu (status == SSH_ERR_MESSAGE_INCOMPLETE)
		trả_về 0;
	không_thì {
		debug_r(status, "%s: channel %d: decode %s",
		    func, c->self, msg);
		trả_về -1;
	}
}

/* try to decode a socks4 header */
static số_nguyên
channel_decode_socks4(Channel *c, struct sshbuf *input, struct sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, dest_addr[4];
	uint16_t dest_port;
	char *user = NULL, *host = NULL;
	số_nguyên success = -1, socks4a = 0, r;
	struct sshbuf *b = NULL;

	nếu (sshbuf_len(input) < 9)
		trả_về 0;

	/* We may not have a complete message, so work on a dup of the buffer */
	nếu ((b = sshbuf_fromb(input)) == NULL)
		fatal_f("sshbuf_fromb failed");

	debug2("channel %d: decode socks4", c->self);
	nếu ((r = sshbuf_get_u8(b, &socks_ver)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0 ||
	    (r = sshbuf_get(b, &dest_addr, sizeof(dest_addr))) != 0 ||
	    (r = sshbuf_get_nulterminated_string(b, 1024, &user, NULL)) != 0) {
		success = socks_decode_error(c, r, __func__, "header");
		goto out;
	}

	/* Is this a SOCKS4A request? (indicated by an address of 0.0.0.x) */
	nếu (dest_addr[0] == 0 && dest_addr[1] == 0 &&
	    dest_addr[2] == 0 && dest_addr[3] != 0) {
		/* If so, then the hostname follows, also nul-terminated */
		nếu ((r = sshbuf_get_nulterminated_string(b, 1024,
		    &host, NULL)) != 0) {
			success = socks_decode_error(c, r, __func__, "host");
			goto out;
		}
		socks4a = 1;
	} không_thì {
		/* Plain SOCKS4 passes an IPv4 binary address; reconstruct */
		xasprintf(&host, "%d.%d.%d.%d",
		    dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);
	}

	/* We have a complete SOCKS4 message; consume it from input */
	nếu ((r = sshbuf_consume_upto_child(input, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Handle the request */
	debug2("channel %d: %s: user=\"%s\" command=%d destination=[%s]:%d",
	    c->self, socks4a ? "SOCKS4A" : "SOCKS4", user, (số_nguyên)socks_cmd,
	    host, dest_port);
	nếu (socks_cmd != 1) {
		debug("channel %d: cannot handle %s command 0x%02x",
		    c->self, socks4a ? "SOCKS4A" : "SOCKS4", socks_cmd);
		goto out;
	}
	free(c->path);
	c->path = host;
	host = NULL; /* transferred */
	c->host_port = dest_port;

	/* Reply to the SOCKS4 client */
	nếu ((r = sshbuf_put_u8(output, 0)) != 0 ||	/* vn: 0 for reply */
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
	trả_về success;
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
static số_nguyên
channel_socks5_check_auth(Channel *c, struct sshbuf *b, struct sshbuf *input,
    struct sshbuf *output)
{
	uint8_t socks_ver;
	uint8_t nmethods, method;
	số_nguyên r;
	u_int i, found;

	/* format: ver | nmethods | methods */
	nếu ((r = sshbuf_get_u8(b, &socks_ver)) != 0)
		trả_về socks_decode_error(c, r, __func__, "version");
	nếu (socks_ver != 5) /* shouldn't happen; checked by caller^2 */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);
	nếu ((r = sshbuf_get_u8(b, &nmethods)) != 0)
		trả_về socks_decode_error(c, r, __func__, "methods");
	cho (found = i = 0; i < nmethods; i++) {
		nếu ((r = sshbuf_get_u8(b, &method)) != 0)
			trả_về socks_decode_error(c, r, __func__, "method");
		nếu (method == SSH_SOCKS5_NOAUTH)
			found = 1;
	}
	nếu (!found) {
		debug("channel %d: didn't request SSH_SOCKS5_NOAUTH", c->self);
		trả_về -1;
	}
	/* Consume completed request */
	nếu ((r = sshbuf_consume_upto_child(input, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	/* Compose reply: version, method */
	nếu ((r = sshbuf_put_u8(output, 0x05)) != 0 ||
	    (r = sshbuf_put_u8(output, SSH_SOCKS5_NOAUTH)) != 0)
		fatal_fr(r, "channel %d: append reply", c->self);
	/* success */
	debug2("channel %d: socks5 auth done", c->self);
	trả_về 1;
}

static số_nguyên
channel_decode_socks5(Channel *c, struct sshbuf *input, struct sshbuf *output)
{
	uint8_t socks_ver, socks_cmd, socks_reserved, socks_atyp, addrlen;
	uint16_t dest_port;
	char dest_addr[255+1], ntop[INET6_ADDRSTRLEN];
	u_int af;
	số_nguyên r, success = -1;;
	struct sshbuf *b = NULL;

	debug2("channel %d: decode socks5 %s", c->self,
	    (c->flags & SSH_SOCKS5_AUTHDONE) ? "request" : "auth");

	/* We may not have a complete message, so work on a dup of the buffer */
	nếu ((b = sshbuf_fromb(input)) == NULL)
		fatal_f("sshbuf_fromb failed");

	nếu (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		nếu ((r = channel_socks5_check_auth(c, b, input, output)) != 1) {
			success = r;
			goto out;
		}
		c->flags |= SSH_SOCKS5_AUTHDONE;
		/* Continue to parse request in case client speculated ahead */
	}

	/* Request messages (auth or connect) always start with the version */
	nếu ((r = sshbuf_get_u8(b, &socks_ver)) != 0) {
		success = socks_decode_error(c, r, __func__, "version");
		goto out;
	}
	nếu (socks_ver != 5) /* shouldn't happen */
		fatal_fr(r, "channel %d: internal error: not socks5", c->self);

	/* Parse SOCKS5 request header */
	debug2("channel %d: socks5 post auth", c->self);
	nếu ((r = sshbuf_get_u8(b, &socks_cmd)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_reserved)) != 0 ||
	    (r = sshbuf_get_u8(b, &socks_atyp)) != 0) {
		success = socks_decode_error(c, r, __func__, "request header");
		goto out;
	}

	nếu (socks_ver != 0x05 ||
	    socks_cmd != SSH_SOCKS5_CONNECT ||
	    socks_reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		goto out;
	}

	switch (socks_atyp) {
	case SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		break;
	case SSH_SOCKS5_DOMAIN:
		nếu ((r = sshbuf_get_u8(b, &addrlen)) != 0) {
			success = socks_decode_error(c, r, __func__, "addrlen");
			goto out;
		}
		af = -1;
		break;
	case SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		break;
	default:
		debug2("channel %d: bad socks5 atyp %d", c->self, socks_atyp);
		goto out;
	}
	nếu ((r = sshbuf_get(b, &dest_addr, addrlen)) != 0 ||
	    (r = sshbuf_get_u16(b, &dest_port)) != 0) {
		success = socks_decode_error(c, r, __func__, "addr/port");
		goto out;
	}
	dest_addr[addrlen] = '\0';

	/* We have a complete SOCKS5 request; consume it from input */
	nếu ((r = sshbuf_consume_upto_child(input, b)) != 0)
		fatal_fr(r, "channel %d: consume", c->self);

	free(c->path);
	c->path = NULL;
	nếu (socks_atyp == SSH_SOCKS5_DOMAIN)
		c->path = xstrdup(dest_addr);
	không_thì {
		nếu (inet_ntop(af, dest_addr, ntop, sizeof(ntop)) == NULL)
			trả_về -1;
		c->path = xstrdup(ntop);
	}
	c->host_port = dest_port;

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->path, c->host_port, socks_cmd);

	/* Reply */
	nếu ((r = sshbuf_put_u8(output, 0x05)) != 0 ||	/* version */
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
	trả_về success;
}

Channel *
channel_connect_stdio_fwd(struct ssh *ssh,
    const char *host_to_connect, số_nguyên port_to_connect,
    số_nguyên in, số_nguyên out, số_nguyên nonblock)
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

	trả_về c;
}

/* dynamic port forwarding */
static void
channel_pre_dynamic(struct ssh *ssh, Channel *c)
{
	u_int have;
	u_char ver;
	số_nguyên r, ret;

	c->io_want = 0;
	have = sshbuf_len(c->input);
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* sshbuf_dump(c->input, stderr); */
	/* check if the fixed size part of the packet is in buffer. */
	nếu (have < 3) {
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		trả_về;
	}
	/* try to guess the protocol */
	nếu ((r = sshbuf_peek_u8(c->input, 0, &ver)) != 0)
		fatal_fr(r, "sshbuf_peek_u8");
	switch (ver) {
	case 0x04:
		ret = channel_decode_socks4(c, c->input, c->output);
		break;
	case 0x05:
		ret = channel_decode_socks5(c, c->input, c->output);
		break;
	default:
		debug2_f("channel %d: unknown SOCKS version %u", c->self, ver);
		ret = -1;
		break;
	}
	nếu (ret < 0) {
		chan_mark_dead(ssh, c);
	} không_thì nếu (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		c->io_want |= SSH_CHAN_IO_RFD;
		nếu (sshbuf_len(c->output))
			c->io_want |= SSH_CHAN_IO_WFD;
	} không_thì {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		port_open_helper(ssh, c, "direct-tcpip");
	}
}

/* simulate read-error */
static void
rdynamic_close(struct ssh *ssh, Channel *c)
{
	c->type = SSH_CHANNEL_OPEN;
	channel_force_close(ssh, c, 0);
}

/* reverse dynamic port forwarding */
static void
channel_before_prepare_io_rdynamic(struct ssh *ssh, Channel *c)
{
	const u_char *p;
	u_int have, len;
	số_nguyên r, ret;

	have = sshbuf_len(c->output);
	debug2("channel %d: pre_rdynamic: have %d", c->self, have);
	/* sshbuf_dump(c->output, stderr); */
	/* EOF received */
	nếu (c->flags & CHAN_EOF_RCVD) {
		nếu ((r = sshbuf_consume(c->output, have)) != 0)
			fatal_fr(r, "channel %d: consume", c->self);
		rdynamic_close(ssh, c);
		trả_về;
	}
	/* check if the fixed size part of the packet is in buffer. */
	nếu (have < 3)
		trả_về;
	/* try to guess the protocol */
	p = sshbuf_ptr(c->output);
	switch (p[0]) {
	case 0x04:
		/* switch input/output for reverse forwarding */
		ret = channel_decode_socks4(c, c->output, c->input);
		break;
	case 0x05:
		ret = channel_decode_socks5(c, c->output, c->input);
		break;
	default:
		ret = -1;
		break;
	}
	nếu (ret < 0) {
		rdynamic_close(ssh, c);
	} không_thì nếu (ret == 0) {
		debug2("channel %d: pre_rdynamic: need more", c->self);
		/* send socks request to peer */
		len = sshbuf_len(c->input);
		nếu (len > 0 && len < c->remote_window) {
			nếu ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_DATA)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, c->input)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				fatal_fr(r, "channel %i: rdynamic", c->self);
			}
			nếu ((r = sshbuf_consume(c->input, len)) != 0)
				fatal_fr(r, "channel %d: consume", c->self);
			c->remote_window -= len;
		}
	} không_thì nếu (rdynamic_connect_finish(ssh, c) < 0) {
		/* the connect failed */
		rdynamic_close(ssh, c);
	}
}

/* This is our fake X11 server socket. */
static void
channel_post_x11_listener(struct ssh *ssh, Channel *c)
{
	Channel *nc;
	struct sockaddr_storage addr;
	số_nguyên r, newsock, oerrno, remote_port;
	socklen_t addrlen;
	char buf[16384], *remote_ipaddr;

	nếu ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		trả_về;

	debug("X11 connection requested.");
	addrlen = sizeof(addr);
	newsock = accept(c->sock, (struct sockaddr *)&addr, &addrlen);
	nếu (c->single_connection) {
		oerrno = errno;
		debug2("single_connection: closing X11 listener.");
		channel_close_fd(ssh, c, &c->sock);
		chan_mark_dead(ssh, c);
		errno = oerrno;
	}
	nếu (newsock == -1) {
		nếu (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		nếu (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		trả_về;
	}
	set_nodelay(newsock);
	nếu (ssh->chanctxt->want_tcp_keepalive)
		set_keepalive(newsock); /* logs errors */
	remote_ipaddr = get_peer_ipaddr(newsock);
	remote_port = get_peer_port(newsock);
	snprintf(buf, sizeof buf, "X11 connection from %.200s port %d",
	    remote_ipaddr, remote_port);

	nc = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, buf, 1);
	open_preamble(ssh, __func__, nc, "x11");
	nếu ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_port)) != 0) {
		fatal_fr(r, "channel %i: reply", c->self);
	}
	nếu ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	free(remote_ipaddr);
}

static void
port_open_helper(struct ssh *ssh, Channel *c, char *rtype)
{
	char *local_ipaddr = get_local_ipaddr(c->sock);
	số_nguyên local_port = c->sock == -1 ? 65536 : get_local_port(c->sock);
	char *remote_ipaddr = get_peer_ipaddr(c->sock);
	số_nguyên remote_port = get_peer_port(c->sock);
	số_nguyên r;

	nếu (remote_port == -1) {
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
	nếu (strcmp(rtype, "direct-tcpip") == 0) {
		/* target host, port */
		nếu ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->host_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} không_thì nếu (strcmp(rtype, "direct-streamlocal@openssh.com") == 0) {
		/* target path */
		nếu ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} không_thì nếu (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* listen path */
		nếu ((r = sshpkt_put_cstring(ssh, c->path)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} không_thì {
		/* listen address, port */
		nếu ((r = sshpkt_put_cstring(ssh, c->path)) != 0 ||
		    (r = sshpkt_put_u32(ssh, local_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	nếu (strcmp(rtype, "forwarded-streamlocal@openssh.com") == 0) {
		/* reserved for future owner/mode info */
		nếu ((r = sshpkt_put_cstring(ssh, "")) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	} không_thì {
		/* originator host and port */
		nếu ((r = sshpkt_put_cstring(ssh, remote_ipaddr)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)remote_port)) != 0)
			fatal_fr(r, "channel %i: reply", c->self);
	}
	nếu ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send", c->self);
	free(remote_ipaddr);
	free(local_ipaddr);
}

void
channel_set_x11_refuse_time(struct ssh *ssh, double refuse_time)
{
	ssh->chanctxt->x11_refuse_time = refuse_time;
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
static void
channel_post_port_listener(struct ssh *ssh, Channel *c)
{
	Channel *nc;
	struct sockaddr_storage addr;
	số_nguyên newsock, nextstate;
	socklen_t addrlen;
	char *rtype;

	nếu ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		trả_về;

	debug("Connection to port %d forwarding to %.100s port %d requested.",
	    c->listening_port, c->path, c->host_port);

	nếu (c->type == SSH_CHANNEL_RPORT_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-tcpip";
	} không_thì nếu (c->type == SSH_CHANNEL_RUNIX_LISTENER) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "forwarded-streamlocal@openssh.com";
	} không_thì nếu (c->host_port == PORT_STREAMLOCAL) {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-streamlocal@openssh.com";
	} không_thì nếu (c->host_port == 0) {
		nextstate = SSH_CHANNEL_DYNAMIC;
		rtype = "dynamic-tcpip";
	} không_thì {
		nextstate = SSH_CHANNEL_OPENING;
		rtype = "direct-tcpip";
	}

	addrlen = sizeof(addr);
	newsock = accept(c->sock, (struct sockaddr *)&addr, &addrlen);
	nếu (newsock == -1) {
		nếu (errno != EINTR && errno != EWOULDBLOCK &&
		    errno != ECONNABORTED)
			error("accept: %.100s", strerror(errno));
		nếu (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		trả_về;
	}
	nếu (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
		set_nodelay(newsock);
		nếu (ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(newsock); /* logs errors */
	}
	nc = channel_new(ssh, rtype, nextstate, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket, 0, rtype, 1);
	nc->listening_port = c->listening_port;
	nc->host_port = c->host_port;
	nếu (c->path != NULL)
		nc->path = xstrdup(c->path);

	nếu (nextstate != SSH_CHANNEL_DYNAMIC)
		port_open_helper(ssh, nc, rtype);
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
static void
channel_post_auth_listener(struct ssh *ssh, Channel *c)
{
	Channel *nc;
	số_nguyên r, newsock;
	struct sockaddr_storage addr;
	socklen_t addrlen;

	nếu ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		trả_về;

	addrlen = sizeof(addr);
	newsock = accept(c->sock, (struct sockaddr *)&addr, &addrlen);
	nếu (newsock == -1) {
		error("accept from auth socket: %.100s", strerror(errno));
		nếu (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		trả_về;
	}
	nc = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPENING, newsock, newsock, -1,
	    c->local_window_max, c->local_maxpacket,
	    0, "accepted auth socket", 1);
	open_preamble(ssh, __func__, nc,
	    c->agent_new ? "agent-connect" : "auth-agent@openssh.com");
	nếu ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i", c->self);
}

static void
channel_post_connecting(struct ssh *ssh, Channel *c)
{
	số_nguyên err = 0, sock, isopen, r;
	socklen_t sz = sizeof(err);

	nếu ((c->io_ready & SSH_CHAN_IO_SOCK_W) == 0)
		trả_về;
	nếu (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	nếu (c->connect_ctx == NULL)
		fatal_f("channel %d: context missing", c->self);

	/* for rdynamic the OPEN_CONFIRMATION has been sent already */
	isopen = (c->type == SSH_CHANNEL_RDYNAMIC_FINISH);

	nếu (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) == -1) {
		err = errno;
		error("getsockopt SO_ERROR failed");
	}

	nếu (err == 0) {
		/* Non-blocking connection completed */
		debug("channel %d: connected to %s port %d",
		    c->self, c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		c->type = SSH_CHANNEL_OPEN;
		channel_set_used_time(ssh, c);
		nếu (isopen) {
			/* no message necessary */
		} không_thì {
			nếu ((r = sshpkt_start(ssh,
			    SSH2_MSG_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i open confirm", c->self);
		}
		trả_về;
	}
	nếu (err == EINTR || err == EAGAIN || err == EINPROGRESS)
		trả_về;

	/* Non-blocking connection failed */
	debug("channel %d: connection failed: %s", c->self, strerror(err));

	/* Try next address, if any */
	nếu ((sock = connect_next(ssh, c->connect_ctx)) == -1) {
		/* Exhausted all addresses for this destination */
		error("connect_to %.100s port %d: failed.",
		    c->connect_ctx->host, c->connect_ctx->port);
		channel_free_connect_ctx(c);
		nếu (isopen) {
			rdynamic_close(ssh, c);
		} không_thì {
			nếu ((r = sshpkt_start(ssh,
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

static số_nguyên
channel_handle_rfd(struct ssh *ssh, Channel *c)
{
	char buf[CHAN_RBUF];
	ssize_t len;
	số_nguyên r, force;
	size_t nr = 0, have, avail, maxlen = CHANNEL_MAX_READ;
	số_nguyên pty_zeroread = 0;

#ifdef PTY_ZEROREAD
	/* Bug on AIX: read(1) can return 0 for a non-closed fd */
	pty_zeroread = c->isatty;
#endif

	force = c->isatty && c->detach_close && c->istate != CHAN_INPUT_CLOSED;

	nếu (!force && (c->io_ready & SSH_CHAN_IO_RFD) == 0)
		trả_về 1;
	nếu ((avail = sshbuf_avail(c->input)) == 0)
		trả_về 1; /* Shouldn't happen */

	/*
	 * For "simple" channels (i.e. not datagram or filtered), we can
	 * read directly to the channel buffer.
	 */
	nếu (!pty_zeroread && c->input_filter == NULL && !c->datagram) {
		/* Only OPEN channels have valid rwin */
		nếu (c->type == SSH_CHANNEL_OPEN) {
			nếu ((have = sshbuf_len(c->input)) >= c->remote_window)
				trả_về 1; /* shouldn't happen */
			nếu (maxlen > c->remote_window - have)
				maxlen = c->remote_window - have;
		}
		nếu (maxlen > avail)
			maxlen = avail;
		nếu ((r = sshbuf_read(c->rfd, c->input, maxlen, &nr)) != 0) {
			nếu (errno == EINTR || (!force &&
			    (errno == EAGAIN || errno == EWOULDBLOCK)))
				trả_về 1;
			debug2("channel %d: read failed rfd %d maxlen %zu: %s",
			    c->self, c->rfd, maxlen, ssh_err(r));
			goto rfail;
		}
		nếu (nr != 0)
			channel_set_used_time(ssh, c);
		trả_về 1;
	}

	errno = 0;
	len = read(c->rfd, buf, sizeof(buf));
	/* fixup AIX zero-length read with errno set to look more like errors */
	nếu (pty_zeroread && len == 0 && errno != 0)
		len = -1;
	nếu (len == -1 && (errno == EINTR ||
	    ((errno == EAGAIN || errno == EWOULDBLOCK) && !force)))
		trả_về 1;
	nếu (len < 0 || (!pty_zeroread && len == 0)) {
		debug2("channel %d: read<=0 rfd %d len %zd: %s",
		    c->self, c->rfd, len,
		    len == 0 ? "closed" : strerror(errno));
 rfail:
		nếu (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			trả_về -1;
		} không_thì {
			chan_read_failed(ssh, c);
		}
		trả_về -1;
	}
	channel_set_used_time(ssh, c);
	nếu (c->input_filter != NULL) {
		nếu (c->input_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
	} không_thì nếu (c->datagram) {
		nếu ((r = sshbuf_put_string(c->input, buf, len)) != 0)
			fatal_fr(r, "channel %i: put datagram", c->self);
	} không_thì nếu ((r = sshbuf_put(c->input, buf, len)) != 0)
		fatal_fr(r, "channel %i: put data", c->self);

	trả_về 1;
}

static số_nguyên
channel_handle_wfd(struct ssh *ssh, Channel *c)
{
	struct termios tio;
	u_char *data = NULL, *buf; /* XXX const; need filter API change */
	size_t dlen, olen = 0;
	số_nguyên r, len;

	nếu ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		trả_về 1;
	nếu (sshbuf_len(c->output) == 0)
		trả_về 1;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	nếu (c->output_filter != NULL) {
		nếu ((buf = c->output_filter(ssh, c, &data, &dlen)) == NULL) {
			debug2("channel %d: filter stops", c->self);
			nếu (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			không_thì
				chan_write_failed(ssh, c);
			trả_về -1;
		}
	} không_thì nếu (c->datagram) {
		nếu ((r = sshbuf_get_string(c->output, &data, &dlen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		buf = data;
	} không_thì {
		buf = data = sshbuf_mutable_ptr(c->output);
		dlen = sshbuf_len(c->output);
	}

	nếu (c->datagram) {
		/* ignore truncated writes, datagrams might get lost */
		len = write(c->wfd, buf, dlen);
		free(data);
		nếu (len == -1 && (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK))
			trả_về 1;
		nếu (len <= 0)
			goto write_fail;
		goto out;
	}

#ifdef _AIX
	/* XXX: Later AIX versions can't push as much data to tty */
	nếu (c->wfd_isatty)
		dlen = MINIMUM(dlen, 8*1024);
#endif

	len = write(c->wfd, buf, dlen);
	nếu (len == -1 &&
	    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
		trả_về 1;
	nếu (len <= 0) {
 write_fail:
		nếu (c->type != SSH_CHANNEL_OPEN) {
			debug2("channel %d: not open", c->self);
			chan_mark_dead(ssh, c);
			trả_về -1;
		} không_thì {
			chan_write_failed(ssh, c);
		}
		trả_về -1;
	}
	channel_set_used_time(ssh, c);
#ifndef BROKEN_TCGETATTR_ICANON
	nếu (c->isatty && dlen >= 1 && buf[0] != '\r') {
		nếu (tcgetattr(c->wfd, &tio) == 0 &&
		    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
			/*
			 * Simulate echo to reduce the impact of
			 * traffic analysis. We need to match the
			 * size of a SSH2_MSG_CHANNEL_DATA message
			 * (4 byte channel id + buf)
			 */
			nếu ((r = sshpkt_msg_ignore(ssh, 4+len)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "channel %i: ignore", c->self);
		}
	}
#endif /* BROKEN_TCGETATTR_ICANON */
	nếu ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
 out:
	c->local_consumed += olen - sshbuf_len(c->output);

	trả_về 1;
}

static số_nguyên
channel_handle_efd_write(struct ssh *ssh, Channel *c)
{
	số_nguyên r;
	ssize_t len;

	nếu ((c->io_ready & SSH_CHAN_IO_EFD_W) == 0)
		trả_về 1;
	nếu (sshbuf_len(c->extended) == 0)
		trả_về 1;

	len = write(c->efd, sshbuf_ptr(c->extended),
	    sshbuf_len(c->extended));
	debug2("channel %d: written %zd to efd %d", c->self, len, c->efd);
	nếu (len == -1 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		trả_về 1;
	nếu (len <= 0) {
		debug2("channel %d: closing write-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
	} không_thì {
		nếu ((r = sshbuf_consume(c->extended, len)) != 0)
			fatal_fr(r, "channel %i: consume", c->self);
		c->local_consumed += len;
		channel_set_used_time(ssh, c);
	}
	trả_về 1;
}

static số_nguyên
channel_handle_efd_read(struct ssh *ssh, Channel *c)
{
	char buf[CHAN_RBUF];
	ssize_t len;
	số_nguyên r, force;

	force = c->isatty && c->detach_close && c->istate != CHAN_INPUT_CLOSED;

	nếu (!force && (c->io_ready & SSH_CHAN_IO_EFD_R) == 0)
		trả_về 1;

	len = read(c->efd, buf, sizeof(buf));
	debug2("channel %d: read %zd from efd %d", c->self, len, c->efd);
	nếu (len == -1 && (errno == EINTR || ((errno == EAGAIN ||
	    errno == EWOULDBLOCK) && !force)))
		trả_về 1;
	nếu (len <= 0) {
		debug2("channel %d: closing read-efd %d", c->self, c->efd);
		channel_close_fd(ssh, c, &c->efd);
		trả_về 1;
	}
	channel_set_used_time(ssh, c);
	nếu (c->extended_usage == CHAN_EXTENDED_IGNORE)
		debug3("channel %d: discard efd", c->self);
	không_thì nếu ((r = sshbuf_put(c->extended, buf, len)) != 0)
		fatal_fr(r, "channel %i: append", c->self);
	trả_về 1;
}

static số_nguyên
channel_handle_efd(struct ssh *ssh, Channel *c)
{
	nếu (c->efd == -1)
		trả_về 1;

	/** XXX handle drain efd, too */

	nếu (c->extended_usage == CHAN_EXTENDED_WRITE)
		trả_về channel_handle_efd_write(ssh, c);
	không_thì nếu (c->extended_usage == CHAN_EXTENDED_READ ||
	    c->extended_usage == CHAN_EXTENDED_IGNORE)
		trả_về channel_handle_efd_read(ssh, c);

	trả_về 1;
}

static số_nguyên
channel_check_window(struct ssh *ssh, Channel *c)
{
	số_nguyên r;

	nếu (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD)) &&
	    ((c->local_window_max - c->local_window >
	    c->local_maxpacket*3) ||
	    c->local_window < c->local_window_max/2) &&
	    c->local_consumed > 0) {
		nếu (!c->have_remote_id)
			fatal_f("channel %d: no remote id", c->self);
		nếu ((r = sshpkt_start(ssh,
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
	trả_về 1;
}

static void
channel_post_open(struct ssh *ssh, Channel *c)
{
	channel_handle_rfd(ssh, c);
	channel_handle_wfd(ssh, c);
	channel_handle_efd(ssh, c);
	channel_check_window(ssh, c);
}

static u_int
read_mux(struct ssh *ssh, Channel *c, u_int need)
{
	char buf[CHAN_RBUF];
	ssize_t len;
	u_int rlen;
	số_nguyên r;

	nếu (sshbuf_len(c->input) < need) {
		rlen = need - sshbuf_len(c->input);
		len = read(c->rfd, buf, MINIMUM(rlen, CHAN_RBUF));
		nếu (len == -1 && (errno == EINTR || errno == EAGAIN))
			trả_về sshbuf_len(c->input);
		nếu (len <= 0) {
			debug2("channel %d: ctl read<=0 rfd %d len %zd",
			    c->self, c->rfd, len);
			chan_read_failed(ssh, c);
			trả_về 0;
		} không_thì nếu ((r = sshbuf_put(c->input, buf, len)) != 0)
			fatal_fr(r, "channel %i: append", c->self);
	}
	trả_về sshbuf_len(c->input);
}

static void
channel_post_mux_client_read(struct ssh *ssh, Channel *c)
{
	u_int need;

	nếu ((c->io_ready & SSH_CHAN_IO_RFD) == 0)
		trả_về;
	nếu (c->istate != CHAN_INPUT_OPEN && c->istate != CHAN_INPUT_WAIT_DRAIN)
		trả_về;
	nếu (c->mux_pause)
		trả_về;

	/*
	 * Don't not read past the precise end of packets to
	 * avoid disrupting fd passing.
	 */
	nếu (read_mux(ssh, c, 4) < 4) /* read header */
		trả_về;
	/* XXX sshbuf_peek_u32 */
	need = PEEK_U32(sshbuf_ptr(c->input));
#define CHANNEL_MUX_MAX_PACKET	(256 * 1024)
	nếu (need > CHANNEL_MUX_MAX_PACKET) {
		debug2("channel %d: packet too big %u > %u",
		    c->self, CHANNEL_MUX_MAX_PACKET, need);
		chan_rcvd_oclose(ssh, c);
		trả_về;
	}
	nếu (read_mux(ssh, c, need + 4) < need + 4) /* read body */
		trả_về;
	nếu (c->mux_rcb(ssh, c) != 0) {
		debug("channel %d: mux_rcb failed", c->self);
		chan_mark_dead(ssh, c);
		trả_về;
	}
}

static void
channel_post_mux_client_write(struct ssh *ssh, Channel *c)
{
	ssize_t len;
	số_nguyên r;

	nếu ((c->io_ready & SSH_CHAN_IO_WFD) == 0)
		trả_về;
	nếu (sshbuf_len(c->output) == 0)
		trả_về;

	len = write(c->wfd, sshbuf_ptr(c->output), sshbuf_len(c->output));
	nếu (len == -1 && (errno == EINTR || errno == EAGAIN))
		trả_về;
	nếu (len <= 0) {
		chan_mark_dead(ssh, c);
		trả_về;
	}
	nếu ((r = sshbuf_consume(c->output, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
}

static void
channel_post_mux_client(struct ssh *ssh, Channel *c)
{
	channel_post_mux_client_read(ssh, c);
	channel_post_mux_client_write(ssh, c);
}

static void
channel_post_mux_listener(struct ssh *ssh, Channel *c)
{
	Channel *nc;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	số_nguyên newsock;
	uid_t euid;
	gid_t egid;

	nếu ((c->io_ready & SSH_CHAN_IO_SOCK_R) == 0)
		trả_về;

	debug("multiplexing control connection");

	/*
	 * Accept connection on control socket
	 */
	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);
	nếu ((newsock = accept(c->sock, (struct sockaddr*)&addr,
	    &addrlen)) == -1) {
		error_f("accept: %s", strerror(errno));
		nếu (errno == EMFILE || errno == ENFILE)
			c->notbefore = monotime_double() + 1.0;
		trả_về;
	}

	nếu (getpeereid(newsock, &euid, &egid) == -1) {
		error_f("getpeereid failed: %s", strerror(errno));
		close(newsock);
		trả_về;
	}
	nếu ((euid != 0) && (getuid() != euid)) {
		error("multiplex uid mismatch: peer euid %u != uid %u",
		    (u_int)euid, (u_int)getuid());
		close(newsock);
		trả_về;
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
channel_handler_init(struct ssh_channels *sc)
{
	chan_fn **pre, **post;

	nếu ((pre = calloc(SSH_CHANNEL_MAX_TYPE, sizeof(*pre))) == NULL ||
	    (post = calloc(SSH_CHANNEL_MAX_TYPE, sizeof(*post))) == NULL)
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
channel_garbage_collect(struct ssh *ssh, Channel *c)
{
	nếu (c == NULL)
		trả_về;
	nếu (c->detach_user != NULL) {
		nếu (!chan_is_dead(ssh, c, c->detach_close))
			trả_về;

		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(ssh, c->self, 0, NULL);
		/* if we still have a callback */
		nếu (c->detach_user != NULL)
			trả_về;
		debug2("channel %d: gc: user detached", c->self);
	}
	nếu (!chan_is_dead(ssh, c, 1))
		trả_về;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(ssh, c);
}

enum channel_table { CHAN_PRE, CHAN_POST };

static void
channel_handler(struct ssh *ssh, số_nguyên table, struct timespec *timeout)
{
	struct ssh_channels *sc = ssh->chanctxt;
	chan_fn **ftab = table == CHAN_PRE ? sc->channel_pre : sc->channel_post;
	u_int i, oalloc;
	Channel *c;
	double now;

	now = monotime_double();
	cho (sc->nbulk = i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		nếu (c == NULL)
			continue;
		/* Count open channels in bulk state */
		nếu (c->type == SSH_CHANNEL_OPEN && c->bulk)
			sc->nbulk++;
		/* Try to keep IO going while rekeying */
		nếu (ssh_packet_is_rekeying(ssh) && c->type != SSH_CHANNEL_OPEN)
			continue;
		nếu (c->delayed) {
			nếu (table == CHAN_PRE)
				c->delayed = 0;
			không_thì
				continue;
		}
		nếu (ftab[c->type] != NULL) {
			nếu (table == CHAN_PRE && c->type == SSH_CHANNEL_OPEN &&
			    channel_get_expiry(ssh, c) != 0 &&
			    now >= channel_get_expiry(ssh, c)) {
				/* channel closed for inactivity */
				double deadline = c->inactive_deadline != 0.0 ?
				    c->inactive_deadline : sc->global_deadline;
				verbose("channel %d: closing after %f seconds "
				    "of inactivity", c->self, deadline);
				channel_force_close(ssh, c, 1);
			} không_thì nếu (c->notbefore <= now) {
				/* Run handlers that are not paused. */
				(*ftab[c->type])(ssh, c);
				/* inactivity timeouts must interrupt poll() */
				nếu (timeout != NULL &&
				    c->type == SSH_CHANNEL_OPEN &&
				    channel_get_expiry(ssh, c) != 0) {
					ptimeout_deadline_monotime_double(timeout,
					    channel_get_expiry(ssh, c));
				}
			} không_thì nếu (timeout != NULL) {
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
channel_before_prepare_io(struct ssh *ssh)
{
	struct ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i, oalloc;

	cho (i = 0, oalloc = sc->channels_alloc; i < oalloc; i++) {
		c = sc->channels[i];
		nếu (c == NULL)
			continue;
		nếu (c->type == SSH_CHANNEL_RDYNAMIC_OPEN)
			channel_before_prepare_io_rdynamic(ssh, c);
	}
}

static void
dump_channel_poll(const char *func, const char *what, Channel *c,
    u_int pollfd_offset, struct pollfd *pfd)
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
    struct pollfd *pfd, u_int npfd)
{
	u_int ev, p = *next_pollfd;

	nếu (c == NULL)
		trả_về;
	nếu (p + 4 > npfd) {
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
	nếu (c->rfd != -1) {
		ev = 0;
		nếu ((c->io_want & SSH_CHAN_IO_RFD) != 0)
			ev |= POLLIN;
		/* rfd == wfd */
		nếu (c->wfd == c->rfd) {
			nếu ((c->io_want & SSH_CHAN_IO_WFD) != 0)
				ev |= POLLOUT;
		}
		/* rfd == efd */
		nếu (c->efd == c->rfd) {
			nếu ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
				ev |= POLLIN;
			nếu ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
				ev |= POLLOUT;
		}
		/* rfd == sock */
		nếu (c->sock == c->rfd) {
			nếu ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
				ev |= POLLIN;
			nếu ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
				ev |= POLLOUT;
		}
		/* Pack a pfd entry if any event armed for this fd */
		nếu (ev != 0) {
			c->pfds[0] = p;
			pfd[p].fd = c->rfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "rfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->wfd if wanting IO and not already handled above */
	nếu (c->wfd != -1 && c->rfd != c->wfd) {
		ev = 0;
		nếu ((c->io_want & SSH_CHAN_IO_WFD))
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		nếu (ev != 0) {
			c->pfds[1] = p;
			pfd[p].fd = c->wfd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "wfd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->efd if wanting IO and not already handled above */
	nếu (c->efd != -1 && c->rfd != c->efd) {
		ev = 0;
		nếu ((c->io_want & SSH_CHAN_IO_EFD_R) != 0)
			ev |= POLLIN;
		nếu ((c->io_want & SSH_CHAN_IO_EFD_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		nếu (ev != 0) {
			c->pfds[2] = p;
			pfd[p].fd = c->efd;
			pfd[p].events = ev;
			dump_channel_poll(__func__, "efd", c, p, &pfd[p]);
			p++;
		}
	}
	/* prepare c->sock if wanting IO and not already handled above */
	nếu (c->sock != -1 && c->rfd != c->sock) {
		ev = 0;
		nếu ((c->io_want & SSH_CHAN_IO_SOCK_R) != 0)
			ev |= POLLIN;
		nếu ((c->io_want & SSH_CHAN_IO_SOCK_W) != 0)
			ev |= POLLOUT;
		/* Pack a pfd entry if any event armed for this fd */
		nếu (ev != 0) {
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
channel_prepare_poll(struct ssh *ssh, struct pollfd **pfdp, u_int *npfd_allocp,
    u_int *npfd_activep, u_int npfd_reserved, struct timespec *timeout)
{
	struct ssh_channels *sc = ssh->chanctxt;
	u_int i, oalloc, p, npfd = npfd_reserved;

	channel_before_prepare_io(ssh); /* might create a new channel */
	/* clear out I/O flags from last poll */
	cho (i = 0; i < sc->channels_alloc; i++) {
		nếu (sc->channels[i] == NULL)
			continue;
		sc->channels[i]->io_want = sc->channels[i]->io_ready = 0;
	}
	/* Allocate 4x pollfd for each channel (rfd, wfd, efd, sock) */
	nếu (sc->channels_alloc >= (INT_MAX / 4) - npfd_reserved)
		fatal_f("too many channels"); /* shouldn't happen */
	npfd += sc->channels_alloc * 4;
	nếu (npfd > *npfd_allocp) {
		*pfdp = xrecallocarray(*pfdp, *npfd_allocp,
		    npfd, sizeof(**pfdp));
		*npfd_allocp = npfd;
	}
	*npfd_activep = npfd_reserved;
	oalloc = sc->channels_alloc;

	channel_handler(ssh, CHAN_PRE, timeout);

	nếu (oalloc != sc->channels_alloc) {
		/* shouldn't happen */
		fatal_f("channels_alloc changed during CHAN_PRE "
		    "(was %u, now %u)", oalloc, sc->channels_alloc);
	}

	/* Prepare pollfd */
	p = npfd_reserved;
	cho (i = 0; i < sc->channels_alloc; i++)
		channel_prepare_pollfd(sc->channels[i], &p, *pfdp, npfd);
	*npfd_activep = p;
}

static void
fd_ready(Channel *c, số_nguyên p, struct pollfd *pfds, u_int npfd, số_nguyên fd,
    const char *what, u_int revents_mask, u_int ready)
{
	struct pollfd *pfd = &pfds[p];

	nếu (fd == -1)
		trả_về;
	nếu (p == -1 || (u_int)p >= npfd)
		fatal_f("channel %d: bad pfd %d (max %u)", c->self, p, npfd);
	dump_channel_poll(__func__, what, c, p, pfd);
	nếu (pfd->fd != fd) {
		fatal("channel %d: inconsistent %s fd=%d pollfd[%u].fd %d "
		    "r%d w%d e%d s%d", c->self, what, fd, p, pfd->fd,
		    c->rfd, c->wfd, c->efd, c->sock);
	}
	nếu ((pfd->revents & POLLNVAL) != 0) {
		fatal("channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d",
		    c->self, what, p, pfd->fd, c->rfd, c->wfd, c->efd, c->sock);
	}
	nếu ((pfd->revents & (revents_mask|POLLHUP|POLLERR)) != 0)
		c->io_ready |= ready & c->io_want;
}

/*
 * After poll, perform any appropriate operations for channels which have
 * events pending.
 */
void
channel_after_poll(struct ssh *ssh, struct pollfd *pfd, u_int npfd)
{
	struct ssh_channels *sc = ssh->chanctxt;
	u_int i;
	số_nguyên p;
	Channel *c;

#ifdef DEBUG_CHANNEL_POLL
	cho (p = 0; p < (số_nguyên)npfd; p++) {
		nếu (pfd[p].revents == 0)
			continue;
		debug_f("pfd[%u].fd %d rev 0x%04x",
		    p, pfd[p].fd, pfd[p].revents);
	}
#endif

	/* Convert pollfd into c->io_ready */
	cho (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		nếu (c == NULL)
			continue;
		/* if rfd is shared with efd/sock then wfd should be too */
		nếu (c->rfd != -1 && c->wfd != -1 && c->rfd != c->wfd &&
		    (c->rfd == c->efd || c->rfd == c->sock)) {
			/* Shouldn't happen */
			fatal_f("channel %d: unexpected fds r%d w%d e%d s%d",
			    c->self, c->rfd, c->wfd, c->efd, c->sock);
		}
		c->io_ready = 0;
		/* rfd, potentially shared with wfd, efd and sock */
		nếu (c->rfd != -1 && (p = c->pfds[0]) != -1) {
			fd_ready(c, p, pfd, npfd, c->rfd,
			    "rfd", POLLIN, SSH_CHAN_IO_RFD);
			nếu (c->rfd == c->wfd) {
				fd_ready(c, p, pfd, npfd, c->wfd,
				    "wfd/r", POLLOUT, SSH_CHAN_IO_WFD);
			}
			nếu (c->rfd == c->efd) {
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdr/r", POLLIN, SSH_CHAN_IO_EFD_R);
				fd_ready(c, p, pfd, npfd, c->efd,
				    "efdw/r", POLLOUT, SSH_CHAN_IO_EFD_W);
			}
			nếu (c->rfd == c->sock) {
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockr/r", POLLIN, SSH_CHAN_IO_SOCK_R);
				fd_ready(c, p, pfd, npfd, c->sock,
				    "sockw/r", POLLOUT, SSH_CHAN_IO_SOCK_W);
			}
			dump_channel_poll(__func__, "rfd", c, p, pfd);
		}
		/* wfd */
		nếu (c->wfd != -1 && c->wfd != c->rfd &&
		    (p = c->pfds[1]) != -1) {
			fd_ready(c, p, pfd, npfd, c->wfd,
			    "wfd", POLLOUT, SSH_CHAN_IO_WFD);
			dump_channel_poll(__func__, "wfd", c, p, pfd);
		}
		/* efd */
		nếu (c->efd != -1 && c->efd != c->rfd &&
		    (p = c->pfds[2]) != -1) {
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdr", POLLIN, SSH_CHAN_IO_EFD_R);
			fd_ready(c, p, pfd, npfd, c->efd,
			    "efdw", POLLOUT, SSH_CHAN_IO_EFD_W);
			dump_channel_poll(__func__, "efd", c, p, pfd);
		}
		/* sock */
		nếu (c->sock != -1 && c->sock != c->rfd &&
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
static số_nguyên
channel_output_poll_input_open(struct ssh *ssh, Channel *c)
{
	size_t len, plen;
	const u_char *pkt;
	số_nguyên r;

	nếu ((len = sshbuf_len(c->input)) == 0) {
		nếu (c->istate == CHAN_INPUT_WAIT_DRAIN) {
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data:
			 * send IEOF.
			 * hack for extended data: delay EOF if EFD still
			 * in use.
			 */
			nếu (CHANNEL_EFD_INPUT_ACTIVE(c))
				debug2("channel %d: "
				    "ibuf_empty delayed efd %d/(%zu)",
				    c->self, c->efd, sshbuf_len(c->extended));
			không_thì
				chan_ibuf_empty(ssh, c);
		}
		trả_về 0;
	}

	nếu (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);

	nếu (c->datagram) {
		/* Check datagram will fit; drop if not */
		nếu ((r = sshbuf_get_string_direct(c->input, &pkt, &plen)) != 0)
			fatal_fr(r, "channel %i: get datagram", c->self);
		/*
		 * XXX this does tail-drop on the datagram queue which is
		 * usually suboptimal compared to head-drop. Better to have
		 * backpressure at read time? (i.e. read + discard)
		 */
		nếu (plen > c->remote_window || plen > c->remote_maxpacket) {
			debug("channel %d: datagram too big", c->self);
			trả_về 0;
		}
		/* Enqueue it */
		nếu ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_DATA)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_put_string(ssh, pkt, plen)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %i: send datagram", c->self);
		c->remote_window -= plen;
		trả_về 1;
	}

	/* Enqueue packet for buffered data. */
	nếu (len > c->remote_window)
		len = c->remote_window;
	nếu (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	nếu (len == 0)
		trả_về 0;
	nếu ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->input), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: send data", c->self);
	nếu ((r = sshbuf_consume(c->input, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	trả_về 1;
}

/*
 * Enqueue data for channels with open c->extended in read mode.
 * Returns non-zero if a packet was enqueued.
 */
static số_nguyên
channel_output_poll_extended_read(struct ssh *ssh, Channel *c)
{
	size_t len;
	số_nguyên r;

	nếu ((len = sshbuf_len(c->extended)) == 0)
		trả_về 0;

	debug2("channel %d: rwin %u elen %zu euse %d", c->self,
	    c->remote_window, sshbuf_len(c->extended), c->extended_usage);
	nếu (len > c->remote_window)
		len = c->remote_window;
	nếu (len > c->remote_maxpacket)
		len = c->remote_maxpacket;
	nếu (len == 0)
		trả_về 0;
	nếu (!c->have_remote_id)
		fatal_f("channel %d: no remote id", c->self);
	nếu ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_EXTENDED_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_EXTENDED_DATA_STDERR)) != 0 ||
	    (r = sshpkt_put_string(ssh, sshbuf_ptr(c->extended), len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %i: data", c->self);
	nếu ((r = sshbuf_consume(c->extended, len)) != 0)
		fatal_fr(r, "channel %i: consume", c->self);
	c->remote_window -= len;
	debug2("channel %d: sent ext data %zu", c->self, len);
	trả_về 1;
}

/*
 * If there is data to send to the connection, enqueue some of it now.
 * Returns non-zero if data was enqueued.
 */
số_nguyên
channel_output_poll(struct ssh *ssh)
{
	struct ssh_channels *sc = ssh->chanctxt;
	Channel *c;
	u_int i;
	số_nguyên ret = 0;

	cho (i = 0; i < sc->channels_alloc; i++) {
		c = sc->channels[i];
		nếu (c == NULL)
			continue;

		/*
		 * We are only interested in channels that can have buffered
		 * incoming data.
		 */
		nếu (c->type != SSH_CHANNEL_OPEN)
			continue;
		nếu ((c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close",
			    c->self);
			continue;
		}

		/* Get the amount of buffered data for this channel. */
		nếu (c->istate == CHAN_INPUT_OPEN ||
		    c->istate == CHAN_INPUT_WAIT_DRAIN)
			ret |= channel_output_poll_input_open(ssh, c);
		/* Send extended data, i.e. stderr */
		nếu (!(c->flags & CHAN_EOF_SENT) &&
		    c->extended_usage == CHAN_EXTENDED_READ)
			ret |= channel_output_poll_extended_read(ssh, c);
	}
	trả_về ret;
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
số_nguyên
channel_proxy_downstream(struct ssh *ssh, Channel *downstream)
{
	Channel *c = NULL;
	struct sshbuf *original = NULL, *modified = NULL;
	const u_char *cp;
	char *ctype = NULL, *listen_host = NULL;
	u_char type;
	size_t have;
	số_nguyên ret = -1, r;
	u_int id, remote_id, listen_port;

	/* sshbuf_dump(downstream->input, stderr); */
	nếu ((r = sshbuf_get_string_direct(downstream->input, &cp, &have))
	    != 0) {
		error_fr(r, "parse");
		trả_về -1;
	}
	nếu (have < 2) {
		error_f("short message");
		trả_về -1;
	}
	type = cp[1];
	/* skip padlen + type */
	cp += 2;
	have -= 2;
	nếu (ssh_packet_log_type(type))
		debug3_f("channel %u: down->up: type %u",
		    downstream->self, type);

	switch (type) {
	case SSH2_MSG_CHANNEL_OPEN:
		nếu ((original = sshbuf_from(cp, have)) == NULL ||
		    (modified = sshbuf_new()) == NULL) {
			error_f("alloc");
			goto out;
		}
		nếu ((r = sshbuf_get_cstring(original, &ctype, NULL)) != 0 ||
		    (r = sshbuf_get_u32(original, &id)) != 0) {
			error_fr(r, "parse");
			goto out;
		}
		c = channel_new(ssh, "mux-proxy", SSH_CHANNEL_MUX_PROXY,
		    -1, -1, -1, 0, 0, 0, ctype, 1);
		c->mux_ctx = downstream;	/* point to mux client */
		c->mux_downstream_id = id;	/* original downstream id */
		nếu ((r = sshbuf_put_cstring(modified, ctype)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			goto out;
		}
		break;
	case SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
		/*
		 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
		 * need to parse 'remote_id' instead of 'ctype'.
		 */
		nếu ((original = sshbuf_from(cp, have)) == NULL ||
		    (modified = sshbuf_new()) == NULL) {
			error_f("alloc");
			goto out;
		}
		nếu ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
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
		nếu ((r = sshbuf_put_u32(modified, remote_id)) != 0 ||
		    (r = sshbuf_put_u32(modified, c->self)) != 0 ||
		    (r = sshbuf_putb(modified, original)) != 0) {
			error_fr(r, "compose");
			channel_free(ssh, c);
			goto out;
		}
		break;
	case SSH2_MSG_GLOBAL_REQUEST:
		nếu ((original = sshbuf_from(cp, have)) == NULL) {
			error_f("alloc");
			goto out;
		}
		nếu ((r = sshbuf_get_cstring(original, &ctype, NULL)) != 0) {
			error_fr(r, "parse");
			goto out;
		}
		nếu (strcmp(ctype, "tcpip-forward") != 0) {
			error_f("unsupported request %s", ctype);
			goto out;
		}
		nếu ((r = sshbuf_get_u8(original, NULL)) != 0 ||
		    (r = sshbuf_get_cstring(original, &listen_host, NULL)) != 0 ||
		    (r = sshbuf_get_u32(original, &listen_port)) != 0) {
			error_fr(r, "parse");
			goto out;
		}
		nếu (listen_port > 65535) {
			error_f("tcpip-forward for %s: bad port %u",
			    listen_host, listen_port);
			goto out;
		}
		/* Record that connection to this host/port is permitted. */
		permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL, "<mux>",
		    -1, listen_host, NULL, (số_nguyên)listen_port, downstream);
		break;
	case SSH2_MSG_CHANNEL_CLOSE:
		nếu (have < 4)
			break;
		remote_id = PEEK_U32(cp);
		nếu ((c = channel_by_remote_id(ssh, remote_id)) != NULL) {
			nếu (c->flags & CHAN_CLOSE_RCVD)
				channel_free(ssh, c);
			không_thì
				c->flags |= CHAN_CLOSE_SENT;
		}
		break;
	}
	nếu (modified) {
		nếu ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_putb(ssh, modified)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			error_fr(r, "send");
			goto out;
		}
	} không_thì {
		nếu ((r = sshpkt_start(ssh, type)) != 0 ||
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
	trả_về ret;
}

/*
 * receive packets from upstream server and de-multiplex packets
 * to correct downstream:
 * implemented as a helper for channel input handlers,
 * replaces local (proxy) channel ID with downstream channel ID.
 */
số_nguyên
channel_proxy_upstream(Channel *c, số_nguyên type, uint32_t seq, struct ssh *ssh)
{
	struct sshbuf *b = NULL;
	Channel *downstream;
	const u_char *cp = NULL;
	size_t len;
	số_nguyên r;

	/*
	 * When receiving packets from the peer we need to check whether we
	 * need to forward the packets to the mux client. In this case we
	 * restore the original channel id and keep track of CLOSE messages,
	 * so we can cleanup the channel.
	 */
	nếu (c == NULL || c->type != SSH_CHANNEL_MUX_PROXY)
		trả_về 0;
	nếu ((downstream = c->mux_ctx) == NULL)
		trả_về 0;
	switch (type) {
	case SSH2_MSG_CHANNEL_CLOSE:
	case SSH2_MSG_CHANNEL_DATA:
	case SSH2_MSG_CHANNEL_EOF:
	case SSH2_MSG_CHANNEL_EXTENDED_DATA:
	case SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
	case SSH2_MSG_CHANNEL_OPEN_FAILURE:
	case SSH2_MSG_CHANNEL_WINDOW_ADJUST:
	case SSH2_MSG_CHANNEL_SUCCESS:
	case SSH2_MSG_CHANNEL_FAILURE:
	case SSH2_MSG_CHANNEL_REQUEST:
		break;
	default:
		debug2_f("channel %u: unsupported type %u", c->self, type);
		trả_về 0;
	}
	nếu ((b = sshbuf_new()) == NULL) {
		error_f("alloc reply");
		goto out;
	}
	/* get remaining payload (after id) */
	cp = sshpkt_ptr(ssh, &len);
	nếu (cp == NULL) {
		error_f("no packet");
		goto out;
	}
	/* translate id and send to muxclient */
	nếu ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
	    (r = sshbuf_put_u8(b, type)) != 0 ||
	    (r = sshbuf_put_u32(b, c->mux_downstream_id)) != 0 ||
	    (r = sshbuf_put(b, cp, len)) != 0 ||
	    (r = sshbuf_put_stringb(downstream->output, b)) != 0) {
		error_fr(r, "compose muxclient");
		goto out;
	}
	/* sshbuf_dump(b, stderr); */
	nếu (ssh_packet_log_type(type))
		debug3_f("channel %u: up->down: type %u", c->self, type);
 out:
	/* update state */
	switch (type) {
	case SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
		/* record remote_id for SSH2_MSG_CHANNEL_CLOSE */
		nếu (cp && len > 4) {
			c->remote_id = PEEK_U32(cp);
			c->have_remote_id = 1;
		}
		break;
	case SSH2_MSG_CHANNEL_CLOSE:
		nếu (c->flags & CHAN_CLOSE_SENT)
			channel_free(ssh, c);
		không_thì
			c->flags |= CHAN_CLOSE_RCVD;
		break;
	}
	sshbuf_free(b);
	trả_về 1;
}

/* -- protocol input */

/* Parse a channel ID from the current packet */
static số_nguyên
channel_parse_id(struct ssh *ssh, const char *where, const char *what)
{
	uint32_t id;
	số_nguyên r;

	nếu ((r = sshpkt_get_u32(ssh, &id)) != 0) {
		error_r(r, "%s: parse id", where);
		ssh_packet_disconnect(ssh, "Invalid %s message", what);
	}
	nếu (id > INT_MAX) {
		error_r(r, "%s: bad channel id %u", where, id);
		ssh_packet_disconnect(ssh, "Invalid %s channel id", what);
	}
	trả_về (số_nguyên)id;
}

/* Lookup a channel from an ID in the current packet */
static Channel *
channel_from_packet_id(struct ssh *ssh, const char *where, const char *what)
{
	số_nguyên id = channel_parse_id(ssh, where, what);
	Channel *c;

	nếu ((c = channel_lookup(ssh, id)) == NULL) {
		ssh_packet_disconnect(ssh,
		    "%s packet referred to nonexistent channel %d", what, id);
	}
	trả_về c;
}

số_nguyên
channel_input_data(số_nguyên type, uint32_t seq, struct ssh *ssh)
{
	const u_char *data;
	size_t data_len, win_len;
	Channel *c = channel_from_packet_id(ssh, __func__, "data");
	số_nguyên r;

	nếu (channel_proxy_upstream(c, type, seq, ssh))
		trả_về 0;

	/* Ignore any data for non-open channels (might happen on close) */
	nếu (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_OPEN &&
	    c->type != SSH_CHANNEL_RDYNAMIC_FINISH &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		trả_về 0;

	/* Get the data. */
	nếu ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "channel %i: get data", c->self);

	win_len = data_len;
	nếu (c->datagram)
		win_len += 4;  /* string length header */

	/*
	 * The sending side reduces its window as it sends data, so we
	 * must 'fake' consumption of the data in order to ensure that window
	 * updates are sent back. Otherwise the connection might deadlock.
	 */
	nếu (c->ostate != CHAN_OUTPUT_OPEN) {
		nếu (win_len > c->local_window)
			c->local_window = 0;
		không_thì
			c->local_window -= win_len;
		c->local_consumed += win_len;
		trả_về 0;
	}

	nếu (win_len > c->local_maxpacket) {
		logit("channel %d: rcvd big packet %zu, maxpack %u",
		    c->self, win_len, c->local_maxpacket);
		trả_về 0;
	}
	nếu (win_len > c->local_window) {
		u_int delta = win_len - c->local_window;

		nếu (c->local_window_exceeded > UINT_MAX - delta)
			c->local_window_exceeded = UINT_MAX;
		không_thì
			c->local_window_exceeded += delta;
		logit("channel %d: rcvd too much data %zu, win %u/%u "
		    "(excess %u)", c->self, win_len, c->local_window,
		    c->local_window_max, c->local_window_exceeded);
		c->local_window = 0;
		/* Allow 10% grace before bringing the hammer down */
		nếu (c->local_window_exceeded > (c->local_window_max / 10)) {
			ssh_packet_disconnect(ssh, "channel %d: peer ignored "
			    "channel window", c->self);
		}
	} không_thì {
		c->local_window -= win_len;
		c->local_window_exceeded = 0;
	}

	nếu (c->datagram) {
		nếu ((r = sshbuf_put_string(c->output, data, data_len)) != 0)
			fatal_fr(r, "channel %i: append datagram", c->self);
	} không_thì nếu ((r = sshbuf_put(c->output, data, data_len)) != 0)
		fatal_fr(r, "channel %i: append data", c->self);

	trả_về 0;
}

số_nguyên
channel_input_extended_data(số_nguyên type, uint32_t seq, struct ssh *ssh)
{
	const u_char *data;
	size_t data_len;
	uint32_t tcode;
	Channel *c = channel_from_packet_id(ssh, __func__, "extended data");
	số_nguyên r;

	nếu (channel_proxy_upstream(c, type, seq, ssh))
		trả_về 0;
	nếu (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", c->self);
		trả_về 0;
	}
	nếu (c->flags & CHAN_EOF_RCVD) {
		nếu (ssh->compat & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof",
			    c->self);
		không_thì
			ssh_packet_disconnect(ssh, "Received extended_data "
			    "after EOF on channel %d.", c->self);
	}

	nếu ((r = sshpkt_get_u32(ssh, &tcode)) != 0) {
		error_fr(r, "parse tcode");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}
	nếu (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_DATA_STDERR) {
		logit("channel %d: bad ext data", c->self);
		trả_về 0;
	}
	nếu ((r = sshpkt_get_string_direct(ssh, &data, &data_len)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid extended_data message");
	}

	nếu (data_len > c->local_window) {
		logit("channel %d: rcvd too much extended_data %zu, win %u",
		    c->self, data_len, c->local_window);
		trả_về 0;
	}
	debug2("channel %d: rcvd ext data %zu", c->self, data_len);
	/* XXX sshpkt_getb? */
	nếu ((r = sshbuf_put(c->extended, data, data_len)) != 0)
		error_fr(r, "append");
	c->local_window -= data_len;
	trả_về 0;
}

số_nguyên
channel_input_ieof(số_nguyên type, uint32_t seq, struct ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "ieof");
	số_nguyên r;

        nếu ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid ieof message");
	}

	nếu (channel_proxy_upstream(c, type, seq, ssh))
		trả_về 0;
	chan_rcvd_ieof(ssh, c);

	/* XXX force input close */
	nếu (c->force_drain && c->istate == CHAN_INPUT_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_INPUT_WAIT_DRAIN;
		nếu (sshbuf_len(c->input) == 0)
			chan_ibuf_empty(ssh, c);
	}
	trả_về 0;
}

số_nguyên
channel_input_oclose(số_nguyên type, uint32_t seq, struct ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "oclose");
	số_nguyên r;

	nếu (channel_proxy_upstream(c, type, seq, ssh))
		trả_về 0;
        nếu ((r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse data");
		ssh_packet_disconnect(ssh, "Invalid oclose message");
	}
	chan_rcvd_oclose(ssh, c);
	trả_về 0;
}

số_nguyên
channel_input_open_confirmation(số_nguyên type, uint32_t seq, struct ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open confirmation");
	uint32_t remote_window, remote_maxpacket;
	số_nguyên r;

	nếu (channel_proxy_upstream(c, type, seq, ssh))
		trả_về 0;
	nếu (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open confirmation for "
		    "non-opening channel %d.", c->self);
	/*
	 * Record the remote channel number and mark that the channel
	 * is now open.
	 */
	nếu ((r = sshpkt_get_u32(ssh, &c->remote_id)) != 0 ||
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
	nếu (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 1, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	channel_set_used_time(ssh, c);
	debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
	    c->remote_window, c->remote_maxpacket);
	trả_về 0;
}

static char *
reason2txt(số_nguyên reason)
{
	switch (reason) {
	case SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		trả_về "administratively prohibited";
	case SSH2_OPEN_CONNECT_FAILED:
		trả_về "connect failed";
	case SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		trả_về "unknown channel type";
	case SSH2_OPEN_RESOURCE_SHORTAGE:
		trả_về "resource shortage";
	}
	trả_về "unknown reason";
}

số_nguyên
channel_input_open_failure(số_nguyên type, uint32_t seq, struct ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	uint32_t reason;
	char *msg = NULL;
	số_nguyên r;

	nếu (channel_proxy_upstream(c, type, seq, ssh))
		trả_về 0;
	nếu (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	nếu ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	nếu ((r = sshpkt_get_cstring(ssh, &msg, NULL)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, NULL, NULL)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), msg ? ": ": "", msg ? msg : "");
	free(msg);
	nếu (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	trả_về 0;
}

số_nguyên
channel_input_window_adjust(số_nguyên type, uint32_t seq, struct ssh *ssh)
{
	số_nguyên id = channel_parse_id(ssh, __func__, "window adjust");
	Channel *c;
	uint32_t adjust;
	u_int new_rwin;
	số_nguyên r;

	nếu ((c = channel_lookup(ssh, id)) == NULL) {
		logit("Received window adjust for non-open channel %d.", id);
		trả_về 0;
	}

	nếu (channel_proxy_upstream(c, type, seq, ssh))
		trả_về 0;
	nếu ((r = sshpkt_get_u32(ssh, &adjust)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse adjust");
		ssh_packet_disconnect(ssh, "Invalid window adjust message");
	}
	debug2("channel %d: rcvd adjust %u", c->self, adjust);
	nếu ((new_rwin = c->remote_window + adjust) < c->remote_window) {
		fatal("channel %d: adjust %u overflows remote window %u",
		    c->self, adjust, c->remote_window);
	}
	c->remote_window = new_rwin;
	trả_về 0;
}

số_nguyên
channel_input_status_confirm(số_nguyên type, uint32_t seq, struct ssh *ssh)
{
	số_nguyên id = channel_parse_id(ssh, __func__, "status confirm");
	Channel *c;
	struct channel_confirm *cc;

	/* Reset keepalive timeout */
	ssh_packet_set_alive_timeouts(ssh, 0);

	debug2_f("type %d id %d", type, id);

	nếu ((c = channel_lookup(ssh, id)) == NULL) {
		logit_f("%d: unknown", id);
		trả_về 0;
	}
	nếu (channel_proxy_upstream(c, type, seq, ssh))
		trả_về 0;
        nếu (sshpkt_get_end(ssh) != 0)
		ssh_packet_disconnect(ssh, "Invalid status confirm message");
	nếu ((cc = TAILQ_FIRST(&c->status_confirms)) == NULL)
		trả_về 0;
	cc->cb(ssh, type, c, cc->ctx);
	TAILQ_REMOVE(&c->status_confirms, cc, entry);
	freezero(cc, sizeof(*cc));
	trả_về 0;
}

/* -- tcp forwarding */

void
channel_set_af(struct ssh *ssh, số_nguyên af)
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
static const char *
channel_fwd_bind_addr(struct ssh *ssh, const char *listen_addr, số_nguyên *wildcardp,
    số_nguyên is_client, struct ForwardOptions *fwd_opts)
{
	const char *addr = NULL;
	số_nguyên wildcard = 0;

	nếu (listen_addr == NULL) {
		/* No address specified: default to gateway_ports setting */
		nếu (fwd_opts->gateway_ports)
			wildcard = 1;
	} không_thì nếu (fwd_opts->gateway_ports || is_client) {
		nếu (((ssh->compat & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0 && is_client == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && fwd_opts->gateway_ports == 1)) {
			wildcard = 1;
			/*
			 * Notify client if they requested a specific listen
			 * address and it was overridden.
			 */
			nếu (*listen_addr != '\0' &&
			    strcmp(listen_addr, "0.0.0.0") != 0 &&
			    strcmp(listen_addr, "*") != 0) {
				ssh_packet_send_debug(ssh,
				    "Forwarding listen address "
				    "\"%s\" overridden by server "
				    "GatewayPorts", listen_addr);
			}
		} không_thì nếu (strcmp(listen_addr, "localhost") != 0 ||
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
	} không_thì nếu (strcmp(listen_addr, "127.0.0.1") == 0 ||
	    strcmp(listen_addr, "::1") == 0) {
		/*
		 * If a specific IPv4/IPv6 localhost address has been
		 * requested then accept it even if gateway_ports is in
		 * effect. This allows the client to prefer IPv4 or IPv6.
		 */
		addr = listen_addr;
	}
	nếu (wildcardp != NULL)
		*wildcardp = wildcard;
	trả_về addr;
}

static số_nguyên
channel_setup_fwd_listener_tcpip(struct ssh *ssh, số_nguyên type,
    struct Forward *fwd, số_nguyên *allocated_listen_port,
    struct ForwardOptions *fwd_opts)
{
	Channel *c;
	số_nguyên sock, r, success = 0, wildcard = 0, is_client;
	struct addrinfo hints, *ai, *aitop;
	const char *host, *addr;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];
	in_port_t *lport_p;

	is_client = (type == SSH_CHANNEL_PORT_LISTENER);

	nếu (is_client && fwd->connect_path != NULL) {
		host = fwd->connect_path;
	} không_thì {
		host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
		    fwd->listen_host : fwd->connect_host;
		nếu (host == NULL) {
			error("No forward host name.");
			trả_về 0;
		}
		nếu (strlen(host) >= NI_MAXHOST) {
			error("Forward host name too long.");
			trả_về 0;
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
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, sizeof strport, "%d", fwd->listen_port);
	nếu ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		nếu (addr == NULL) {
			/* This really shouldn't happen */
			ssh_packet_disconnect(ssh, "getaddrinfo: fatal error: %s",
			    ssh_gai_strerror(r));
		} không_thì {
			error_f("getaddrinfo(%.64s): %s", addr,
			    ssh_gai_strerror(r));
		}
		trả_về 0;
	}
	nếu (allocated_listen_port != NULL)
		*allocated_listen_port = 0;
	cho (ai = aitop; ai; ai = ai->ai_next) {
		switch (ai->ai_family) {
		case AF_INET:
			lport_p = &((struct sockaddr_in *)ai->ai_addr)->
			    sin_port;
			break;
		case AF_INET6:
			lport_p = &((struct sockaddr_in6 *)ai->ai_addr)->
			    sin6_port;
			break;
		default:
			continue;
		}
		/*
		 * If allocating a port for -R forwards, then use the
		 * same port for all address families.
		 */
		nếu (type == SSH_CHANNEL_RPORT_LISTENER &&
		    fwd->listen_port == 0 && allocated_listen_port != NULL &&
		    *allocated_listen_port > 0)
			*lport_p = htons(*allocated_listen_port);

		nếu (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, sizeof(ntop),
		    strport, sizeof(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error_f("getnameinfo failed");
			continue;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		nếu (sock == -1) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			continue;
		}

		set_reuseaddr(sock);
		nếu (ai->ai_family == AF_INET6)
			sock_set_v6only(sock);

		debug("Local forwarding listening on %s port %s.",
		    ntop, strport);

		/* Bind the socket to the address. */
		nếu (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			/*
			 * address can be in if use ipv6 address is
			 * already bound
			 */
			nếu (!ai->ai_next)
				error("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));
			không_thì
				verbose("bind [%s]:%s: %.100s",
				    ntop, strport, strerror(errno));

			close(sock);
			continue;
		}
		/* Start listening for connections on the socket. */
		nếu (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen [%s]:%s: %.100s", ntop, strport,
			    strerror(errno));
			close(sock);
			continue;
		}

		/*
		 * fwd->listen_port == 0 requests a dynamically allocated port -
		 * record what we got.
		 */
		nếu (type == SSH_CHANNEL_RPORT_LISTENER &&
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
		nếu (fwd->listen_port == 0 && allocated_listen_port != NULL &&
		    !(ssh->compat & SSH_BUG_DYNAMIC_RPORT))
			c->listening_port = *allocated_listen_port;
		không_thì
			c->listening_port = fwd->listen_port;
		success = 1;
	}
	nếu (success == 0)
		error_f("cannot listen to port: %d", fwd->listen_port);
	freeaddrinfo(aitop);
	trả_về success;
}

static số_nguyên
channel_setup_fwd_listener_streamlocal(struct ssh *ssh, số_nguyên type,
    struct Forward *fwd, struct ForwardOptions *fwd_opts)
{
	struct sockaddr_un sunaddr;
	const char *path;
	Channel *c;
	số_nguyên port, sock;
	mode_t omask;

	switch (type) {
	case SSH_CHANNEL_UNIX_LISTENER:
		nếu (fwd->connect_path != NULL) {
			nếu (strlen(fwd->connect_path) > sizeof(sunaddr.sun_path)) {
				error("Local connecting path too long: %s",
				    fwd->connect_path);
				trả_về 0;
			}
			path = fwd->connect_path;
			port = PORT_STREAMLOCAL;
		} không_thì {
			nếu (fwd->connect_host == NULL) {
				error("No forward host name.");
				trả_về 0;
			}
			nếu (strlen(fwd->connect_host) >= NI_MAXHOST) {
				error("Forward host name too long.");
				trả_về 0;
			}
			path = fwd->connect_host;
			port = fwd->connect_port;
		}
		break;
	case SSH_CHANNEL_RUNIX_LISTENER:
		path = fwd->listen_path;
		port = PORT_STREAMLOCAL;
		break;
	default:
		error_f("unexpected channel type %d", type);
		trả_về 0;
	}

	nếu (fwd->listen_path == NULL) {
		error("No forward path name.");
		trả_về 0;
	}
	nếu (strlen(fwd->listen_path) > sizeof(sunaddr.sun_path)) {
		error("Local listening path too long: %s", fwd->listen_path);
		trả_về 0;
	}

	debug3_f("type %d path %s", type, fwd->listen_path);

	/* Start a Unix domain listener. */
	omask = umask(fwd_opts->streamlocal_bind_mask);
	sock = unix_listener(fwd->listen_path, SSH_LISTEN_BACKLOG,
	    fwd_opts->streamlocal_bind_unlink);
	umask(omask);
	nếu (sock < 0)
		trả_về 0;

	debug("Local forwarding listening on path %s.", fwd->listen_path);

	/* Allocate a channel number for the socket. */
	c = channel_new(ssh, "unix-listener", type, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, "unix listener", 1);
	c->path = xstrdup(path);
	c->host_port = port;
	c->listening_port = PORT_STREAMLOCAL;
	c->listening_addr = xstrdup(fwd->listen_path);
	trả_về 1;
}

static số_nguyên
channel_cancel_rport_listener_tcpip(struct ssh *ssh,
    const char *host, u_short port)
{
	u_int i;
	số_nguyên found = 0;

	cho (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		nếu (c == NULL || c->type != SSH_CHANNEL_RPORT_LISTENER)
			continue;
		nếu (strcmp(c->path, host) == 0 && c->listening_port == port) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	trả_về found;
}

static số_nguyên
channel_cancel_rport_listener_streamlocal(struct ssh *ssh, const char *path)
{
	u_int i;
	số_nguyên found = 0;

	cho (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		nếu (c == NULL || c->type != SSH_CHANNEL_RUNIX_LISTENER)
			continue;
		nếu (c->path == NULL)
			continue;
		nếu (strcmp(c->path, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	trả_về found;
}

số_nguyên
channel_cancel_rport_listener(struct ssh *ssh, struct Forward *fwd)
{
	nếu (fwd->listen_path != NULL) {
		trả_về channel_cancel_rport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} không_thì {
		trả_về channel_cancel_rport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port);
	}
}

static số_nguyên
channel_cancel_lport_listener_tcpip(struct ssh *ssh,
    const char *lhost, u_short lport, số_nguyên cport,
    struct ForwardOptions *fwd_opts)
{
	u_int i;
	số_nguyên found = 0;
	const char *addr = channel_fwd_bind_addr(ssh, lhost, NULL, 1, fwd_opts);

	cho (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		nếu (c == NULL || c->type != SSH_CHANNEL_PORT_LISTENER)
			continue;
		nếu (c->listening_port != lport)
			continue;
		nếu (cport == CHANNEL_CANCEL_PORT_STATIC) {
			/* skip dynamic forwardings */
			nếu (c->host_port == 0)
				continue;
		} không_thì {
			nếu (c->host_port != cport)
				continue;
		}
		nếu ((c->listening_addr == NULL && addr != NULL) ||
		    (c->listening_addr != NULL && addr == NULL))
			continue;
		nếu (addr == NULL || strcmp(c->listening_addr, addr) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	trả_về found;
}

static số_nguyên
channel_cancel_lport_listener_streamlocal(struct ssh *ssh, const char *path)
{
	u_int i;
	số_nguyên found = 0;

	nếu (path == NULL) {
		error_f("no path specified.");
		trả_về 0;
	}

	cho (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		Channel *c = ssh->chanctxt->channels[i];
		nếu (c == NULL || c->type != SSH_CHANNEL_UNIX_LISTENER)
			continue;
		nếu (c->listening_addr == NULL)
			continue;
		nếu (strcmp(c->listening_addr, path) == 0) {
			debug2_f("close channel %d", i);
			channel_free(ssh, c);
			found = 1;
		}
	}

	trả_về found;
}

số_nguyên
channel_cancel_lport_listener(struct ssh *ssh,
    struct Forward *fwd, số_nguyên cport, struct ForwardOptions *fwd_opts)
{
	nếu (fwd->listen_path != NULL) {
		trả_về channel_cancel_lport_listener_streamlocal(ssh,
		    fwd->listen_path);
	} không_thì {
		trả_về channel_cancel_lport_listener_tcpip(ssh,
		    fwd->listen_host, fwd->listen_port, cport, fwd_opts);
	}
}

/* protocol local port fwd, used by ssh */
số_nguyên
channel_setup_local_fwd_listener(struct ssh *ssh,
    struct Forward *fwd, struct ForwardOptions *fwd_opts)
{
	nếu (fwd->listen_path != NULL) {
		trả_về channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_UNIX_LISTENER, fwd, fwd_opts);
	} không_thì {
		trả_về channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_PORT_LISTENER, fwd, NULL, fwd_opts);
	}
}

/* Matches a remote forwarding permission against a requested forwarding */
static số_nguyên
remote_open_match(struct permission *allowed_open, struct Forward *fwd)
{
	số_nguyên ret;
	char *lhost;

	/* XXX add ACLs for streamlocal */
	nếu (fwd->listen_path != NULL)
		trả_về 1;

	nếu (fwd->listen_host == NULL || allowed_open->listen_host == NULL)
		trả_về 0;

	nếu (allowed_open->listen_port != FWD_PERMIT_ANY_PORT &&
	    allowed_open->listen_port != fwd->listen_port)
		trả_về 0;

	/* Match hostnames case-insensitively */
	lhost = xstrdup(fwd->listen_host);
	lowercase(lhost);
	ret = match_pattern(lhost, allowed_open->listen_host);
	free(lhost);

	trả_về ret;
}

/* Checks whether a requested remote forwarding is permitted */
static số_nguyên
check_rfwd_permission(struct ssh *ssh, struct Forward *fwd)
{
	struct ssh_channels *sc = ssh->chanctxt;
	struct permission_set *pset = &sc->remote_perms;
	u_int i, permit, permit_adm = 1;
	struct permission *perm;

#ifdef SKIP_PRIVDROP
	nếu (fwd->listen_path != NULL)
		trả_về 0;
	nếu (fwd->listen_port != 0 && fwd->listen_port < 1024)
		trả_về 0;
#endif

	/* XXX apply GatewayPorts override before checking? */

	permit = pset->all_permitted;
	nếu (!permit) {
		cho (i = 0; i < pset->num_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			nếu (remote_open_match(perm, fwd)) {
				permit = 1;
				break;
			}
		}
	}

	nếu (pset->num_permitted_admin > 0) {
		permit_adm = 0;
		cho (i = 0; i < pset->num_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			nếu (remote_open_match(perm, fwd)) {
				permit_adm = 1;
				break;
			}
		}
	}

	trả_về permit && permit_adm;
}

/* protocol v2 remote port fwd, used by sshd */
số_nguyên
channel_setup_remote_fwd_listener(struct ssh *ssh, struct Forward *fwd,
    số_nguyên *allocated_listen_port, struct ForwardOptions *fwd_opts)
{
	nếu (!check_rfwd_permission(ssh, fwd)) {
		ssh_packet_send_debug(ssh, "port forwarding refused");
		nếu (fwd->listen_path != NULL)
			/* XXX always allowed, see remote_open_match() */
			logit("Received request from %.100s port %d to "
			    "remote forward to path \"%.100s\", "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_path);
		không_thì nếu(fwd->listen_host != NULL)
			logit("Received request from %.100s port %d to "
			    "remote forward to host %.100s port %d, "
			    "but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
			    fwd->listen_host, fwd->listen_port );
		không_thì
			logit("Received request from %.100s port %d to remote "
			    "forward, but the request was denied.",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		trả_về 0;
	}
	nếu (fwd->listen_path != NULL) {
		trả_về channel_setup_fwd_listener_streamlocal(ssh,
		    SSH_CHANNEL_RUNIX_LISTENER, fwd, fwd_opts);
	} không_thì {
		trả_về channel_setup_fwd_listener_tcpip(ssh,
		    SSH_CHANNEL_RPORT_LISTENER, fwd, allocated_listen_port,
		    fwd_opts);
	}
}

/*
 * Translate the requested rfwd listen host to something usable for
 * this server.
 */
static const char *
channel_rfwd_bind_host(const char *listen_host)
{
	nếu (listen_host == NULL) {
		trả_về "localhost";
	} không_thì nếu (*listen_host == '\0' || strcmp(listen_host, "*") == 0) {
		trả_về "";
	} không_thì
		trả_về listen_host;
}

/*
 * Initiate forwarding of connections to port "port" on remote host through
 * the secure channel to host:port from local side.
 * Returns handle (index) for updating the dynamic listen port with
 * channel_update_permission().
 */
số_nguyên
channel_request_remote_forwarding(struct ssh *ssh, struct Forward *fwd)
{
	số_nguyên r, success = 0, idx = -1;
	const char *host_to_connect, *listen_host, *listen_path;
	số_nguyên port_to_connect, listen_port;

	/* Send the forward request to the remote side. */
	nếu (fwd->listen_path != NULL) {
		nếu ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "streamlocal-forward@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0 || /* want reply */
		    (r = sshpkt_put_cstring(ssh, fwd->listen_path)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "request streamlocal");
	} không_thì {
		nếu ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
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
	nếu (success) {
		/* Record that connection to this host/port is permitted. */
		host_to_connect = listen_host = listen_path = NULL;
		port_to_connect = listen_port = 0;
		nếu (fwd->connect_path != NULL) {
			host_to_connect = fwd->connect_path;
			port_to_connect = PORT_STREAMLOCAL;
		} không_thì {
			host_to_connect = fwd->connect_host;
			port_to_connect = fwd->connect_port;
		}
		nếu (fwd->listen_path != NULL) {
			listen_path = fwd->listen_path;
			listen_port = PORT_STREAMLOCAL;
		} không_thì {
			listen_host = fwd->listen_host;
			listen_port = fwd->listen_port;
		}
		idx = permission_set_add(ssh, FORWARD_USER, FORWARD_LOCAL,
		    host_to_connect, port_to_connect,
		    listen_host, listen_path, listen_port, NULL);
	}
	trả_về idx;
}

static số_nguyên
open_match(struct permission *allowed_open, const char *requestedhost,
    số_nguyên requestedport)
{
	nếu (allowed_open->host_to_connect == NULL)
		trả_về 0;
	nếu (allowed_open->port_to_connect != FWD_PERMIT_ANY_PORT &&
	    allowed_open->port_to_connect != requestedport)
		trả_về 0;
	nếu (strcmp(allowed_open->host_to_connect, FWD_PERMIT_ANY_HOST) != 0 &&
	    strcmp(allowed_open->host_to_connect, requestedhost) != 0)
		trả_về 0;
	trả_về 1;
}

/*
 * Note that in the listen host/port case
 * we don't support FWD_PERMIT_ANY_PORT and
 * need to translate between the configured-host (listen_host)
 * and what we've sent to the remote server (channel_rfwd_bind_host)
 */
static số_nguyên
open_listen_match_tcpip(struct permission *allowed_open,
    const char *requestedhost, u_short requestedport, số_nguyên translate)
{
	const char *allowed_host;

	nếu (allowed_open->host_to_connect == NULL)
		trả_về 0;
	nếu (allowed_open->listen_port != requestedport)
		trả_về 0;
	nếu (!translate && allowed_open->listen_host == NULL &&
	    requestedhost == NULL)
		trả_về 1;
	allowed_host = translate ?
	    channel_rfwd_bind_host(allowed_open->listen_host) :
	    allowed_open->listen_host;
	nếu (allowed_host == NULL || requestedhost == NULL ||
	    strcmp(allowed_host, requestedhost) != 0)
		trả_về 0;
	trả_về 1;
}

static số_nguyên
open_listen_match_streamlocal(struct permission *allowed_open,
    const char *requestedpath)
{
	nếu (allowed_open->host_to_connect == NULL)
		trả_về 0;
	nếu (allowed_open->listen_port != PORT_STREAMLOCAL)
		trả_về 0;
	nếu (allowed_open->listen_path == NULL ||
	    strcmp(allowed_open->listen_path, requestedpath) != 0)
		trả_về 0;
	trả_về 1;
}

/*
 * Request cancellation of remote forwarding of connection host:port from
 * local side.
 */
static số_nguyên
channel_request_rforward_cancel_tcpip(struct ssh *ssh,
    const char *host, u_short port)
{
	struct ssh_channels *sc = ssh->chanctxt;
	struct permission_set *pset = &sc->local_perms;
	số_nguyên r;
	u_int i;
	struct permission *perm = NULL;

	cho (i = 0; i < pset->num_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		nếu (open_listen_match_tcpip(perm, host, port, 0))
			break;
		perm = NULL;
	}
	nếu (perm == NULL) {
		debug_f("requested forward not found");
		trả_về -1;
	}
	nếu ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "cancel-tcpip-forward")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host))) != 0 ||
	    (r = sshpkt_put_u32(ssh, port)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	trả_về 0;
}

/*
 * Request cancellation of remote forwarding of Unix domain socket
 * path from local side.
 */
static số_nguyên
channel_request_rforward_cancel_streamlocal(struct ssh *ssh, const char *path)
{
	struct ssh_channels *sc = ssh->chanctxt;
	struct permission_set *pset = &sc->local_perms;
	số_nguyên r;
	u_int i;
	struct permission *perm = NULL;

	cho (i = 0; i < pset->num_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		nếu (open_listen_match_streamlocal(perm, path))
			break;
		perm = NULL;
	}
	nếu (perm == NULL) {
		debug_f("requested forward not found");
		trả_về -1;
	}
	nếu ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "cancel-streamlocal-forward@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 || /* want reply */
	    (r = sshpkt_put_cstring(ssh, path)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send cancel");

	fwd_perm_clear(perm); /* unregister */

	trả_về 0;
}

/*
 * Request cancellation of remote forwarding of a connection from local side.
 */
số_nguyên
channel_request_rforward_cancel(struct ssh *ssh, struct Forward *fwd)
{
	nếu (fwd->listen_path != NULL) {
		trả_về channel_request_rforward_cancel_streamlocal(ssh,
		    fwd->listen_path);
	} không_thì {
		trả_về channel_request_rforward_cancel_tcpip(ssh,
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
channel_permit_all(struct ssh *ssh, số_nguyên where)
{
	struct permission_set *pset = permission_set_get(ssh, where);

	nếu (pset->num_permitted_user == 0)
		pset->all_permitted = 1;
}

/*
 * Permit the specified host/port for forwarding.
 */
void
channel_add_permission(struct ssh *ssh, số_nguyên who, số_nguyên where,
    char *host, số_nguyên port)
{
	số_nguyên local = where == FORWARD_LOCAL;
	struct permission_set *pset = permission_set_get(ssh, where);

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
channel_disable_admin(struct ssh *ssh, số_nguyên where)
{
	channel_clear_permission(ssh, FORWARD_ADM, where);
	permission_set_add(ssh, FORWARD_ADM, where,
	    NULL, 0, NULL, NULL, 0, NULL);
}

/*
 * Clear a list of permitted opens.
 */
void
channel_clear_permission(struct ssh *ssh, số_nguyên who, số_nguyên where)
{
	struct permission **permp;
	u_int i, *npermp;

	permission_set_get_array(ssh, who, where, &permp, &npermp);
	cho (i = 0; i < *npermp; i++)
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
channel_update_permission(struct ssh *ssh, số_nguyên idx, số_nguyên newport)
{
	struct permission_set *pset = &ssh->chanctxt->local_perms;

	nếu (idx < 0 || (u_int)idx >= pset->num_permitted_user) {
		debug_f("index out of range: %d num_permitted_user %d",
		    idx, pset->num_permitted_user);
		trả_về;
	}
	debug("%s allowed port %d for forwarding to host %s port %d",
	    newport > 0 ? "Updating" : "Removing",
	    newport,
	    pset->permitted_user[idx].host_to_connect,
	    pset->permitted_user[idx].port_to_connect);
	nếu (newport <= 0)
		fwd_perm_clear(&pset->permitted_user[idx]);
	không_thì {
		pset->permitted_user[idx].listen_port =
		    (ssh->compat & SSH_BUG_DYNAMIC_RPORT) ? 0 : newport;
	}
}

/* Try to start non-blocking connect to next host in cctx list */
static số_nguyên
connect_next(struct ssh *ssh, struct channel_connect *cctx)
{
	số_nguyên sock, sock_is_network, saved_errno;
	struct sockaddr_un *sunaddr;
	char ntop[NI_MAXHOST];
	char strport[MAXIMUM(NI_MAXSERV, sizeof(sunaddr->sun_path))];

	cho (; cctx->ai; cctx->ai = cctx->ai->ai_next) {
		sock_is_network = 0;
		switch (cctx->ai->ai_family) {
		case AF_UNIX:
			/* unix:pathname instead of host:port */
			sunaddr = (struct sockaddr_un *)cctx->ai->ai_addr;
			strlcpy(ntop, "unix", sizeof(ntop));
			strlcpy(strport, sunaddr->sun_path, sizeof(strport));
			break;
		case AF_INET:
		case AF_INET6:
			nếu (getnameinfo(cctx->ai->ai_addr, cctx->ai->ai_addrlen,
			    ntop, sizeof(ntop), strport, sizeof(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error_f("getnameinfo failed");
				continue;
			}
			sock_is_network = 1;
			break;
		default:
			continue;
		}
		debug_f("start for host %.100s ([%.100s]:%s)",
		    cctx->host, ntop, strport);
		nếu ((sock = socket(cctx->ai->ai_family, cctx->ai->ai_socktype,
		    cctx->ai->ai_protocol)) == -1) {
			nếu (cctx->ai->ai_next == NULL)
				error("socket: %.100s", strerror(errno));
			không_thì
				verbose("socket: %.100s", strerror(errno));
			continue;
		}
		nếu (set_nonblock(sock) == -1)
			fatal_f("set_nonblock(%d)", sock);
		nếu (sock_is_network && ssh->chanctxt->want_tcp_keepalive)
			set_keepalive(sock); /* logs errors */
		nếu (connect(sock, cctx->ai->ai_addr,
		    cctx->ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
			debug_f("host %.100s ([%.100s]:%s): %.100s",
			    cctx->host, ntop, strport, strerror(errno));
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			continue;	/* fail -- try next */
		}
		nếu (cctx->ai->ai_family != AF_UNIX)
			set_nodelay(sock);
		debug_f("connect host %.100s ([%.100s]:%s) in progress, fd=%d",
		    cctx->host, ntop, strport, sock);
		cctx->ai = cctx->ai->ai_next;
		trả_về sock;
	}
	trả_về -1;
}

/*
 * Return connecting socket to remote host:port or local socket path,
 * passing back the failure reason if appropriate.
 */
static số_nguyên
connect_to_helper(struct ssh *ssh, const char *name, số_nguyên port, số_nguyên socktype,
    char *ctype, char *rname, struct channel_connect *cctx,
    số_nguyên *reason, const char **errmsg)
{
	struct addrinfo hints;
	số_nguyên gaierr;
	số_nguyên sock = -1;
	char strport[NI_MAXSERV];

	nếu (port == PORT_STREAMLOCAL) {
		struct sockaddr_un *sunaddr;
		struct addrinfo *ai;

		nếu (strlen(name) > sizeof(sunaddr->sun_path)) {
			error("%.100s: %.100s", name, strerror(ENAMETOOLONG));
			trả_về -1;
		}

		/*
		 * Fake up a struct addrinfo for AF_UNIX connections.
		 * free_connect_ctx() must check ai_family
		 * and use free() not freeaddrinfo() for AF_UNIX.
		 */
		ai = xcalloc(1, sizeof(*ai) + sizeof(*sunaddr));
		ai->ai_addr = (struct sockaddr *)(ai + 1);
		ai->ai_addrlen = sizeof(*sunaddr);
		ai->ai_family = AF_UNIX;
		ai->ai_socktype = socktype;
		ai->ai_protocol = PF_UNSPEC;
		sunaddr = (struct sockaddr_un *)ai->ai_addr;
		sunaddr->sun_family = AF_UNIX;
		strlcpy(sunaddr->sun_path, name, sizeof(sunaddr->sun_path));
		cctx->aitop = ai;
	} không_thì {
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_socktype = socktype;
		snprintf(strport, sizeof strport, "%d", port);
		nếu ((gaierr = getaddrinfo(name, strport, &hints, &cctx->aitop))
		    != 0) {
			nếu (errmsg != NULL)
				*errmsg = ssh_gai_strerror(gaierr);
			nếu (reason != NULL)
				*reason = SSH2_OPEN_CONNECT_FAILED;
			error("connect_to %.100s: unknown host (%s)", name,
			    ssh_gai_strerror(gaierr));
			trả_về -1;
		}
	}

	cctx->host = xstrdup(name);
	cctx->port = port;
	cctx->ai = cctx->aitop;

	nếu ((sock = connect_next(ssh, cctx)) == -1) {
		error("connect to %.100s port %d failed: %s",
		    name, port, strerror(errno));
		trả_về -1;
	}

	trả_về sock;
}

/* Return CONNECTING channel to remote host:port or local socket path */
static Channel *
connect_to(struct ssh *ssh, const char *host, số_nguyên port,
    char *ctype, char *rname)
{
	struct channel_connect cctx;
	Channel *c;
	số_nguyên sock;

	memset(&cctx, 0, sizeof(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, NULL, NULL);
	nếu (sock == -1) {
		free_connect_ctx(&cctx);
		trả_về NULL;
	}
	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(sizeof(cctx));
	memcpy(c->connect_ctx, &cctx, sizeof(cctx));

	trả_về c;
}

/*
 * returns either the newly connected channel or the downstream channel
 * that needs to deal with this connection.
 */
Channel *
channel_connect_by_listen_address(struct ssh *ssh, const char *listen_host,
    u_short listen_port, char *ctype, char *rname)
{
	struct ssh_channels *sc = ssh->chanctxt;
	struct permission_set *pset = &sc->local_perms;
	u_int i;
	struct permission *perm;

	cho (i = 0; i < pset->num_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		nếu (open_listen_match_tcpip(perm,
		    listen_host, listen_port, 1)) {
			nếu (perm->downstream)
				trả_về perm->downstream;
			nếu (perm->port_to_connect == 0)
				trả_về rdynamic_connect_prepare(ssh,
				    ctype, rname);
			trả_về connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_port);
	trả_về NULL;
}

Channel *
channel_connect_by_listen_path(struct ssh *ssh, const char *path,
    char *ctype, char *rname)
{
	struct ssh_channels *sc = ssh->chanctxt;
	struct permission_set *pset = &sc->local_perms;
	u_int i;
	struct permission *perm;

	cho (i = 0; i < pset->num_permitted_user; i++) {
		perm = &pset->permitted_user[i];
		nếu (open_listen_match_streamlocal(perm, path)) {
			trả_về connect_to(ssh,
			    perm->host_to_connect, perm->port_to_connect,
			    ctype, rname);
		}
	}
	error("WARNING: Server requests forwarding for unknown path %.100s",
	    path);
	trả_về NULL;
}

/* Check if connecting to that port is permitted and connect. */
Channel *
channel_connect_to_port(struct ssh *ssh, const char *host, u_short port,
    char *ctype, char *rname, số_nguyên *reason, const char **errmsg)
{
	struct ssh_channels *sc = ssh->chanctxt;
	struct permission_set *pset = &sc->local_perms;
	struct channel_connect cctx;
	Channel *c;
	u_int i, permit, permit_adm = 1;
	số_nguyên sock;
	struct permission *perm;

	permit = pset->all_permitted;
	nếu (!permit) {
		cho (i = 0; i < pset->num_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			nếu (open_match(perm, host, port)) {
				permit = 1;
				break;
			}
		}
	}

	nếu (pset->num_permitted_admin > 0) {
		permit_adm = 0;
		cho (i = 0; i < pset->num_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			nếu (open_match(perm, host, port)) {
				permit_adm = 1;
				break;
			}
		}
	}

	nếu (!permit || !permit_adm) {
		logit("Received request from %.100s port %d to connect to "
		    "host %.100s port %d, but the request was denied.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), host, port);
		nếu (reason != NULL)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		trả_về NULL;
	}

	memset(&cctx, 0, sizeof(cctx));
	sock = connect_to_helper(ssh, host, port, SOCK_STREAM, ctype, rname,
	    &cctx, reason, errmsg);
	nếu (sock == -1) {
		free_connect_ctx(&cctx);
		trả_về NULL;
	}

	c = channel_new(ssh, ctype, SSH_CHANNEL_CONNECTING, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = port;
	c->path = xstrdup(host);
	c->connect_ctx = xmalloc(sizeof(cctx));
	memcpy(c->connect_ctx, &cctx, sizeof(cctx));

	trả_về c;
}

/* Check if connecting to that path is permitted and connect. */
Channel *
channel_connect_to_path(struct ssh *ssh, const char *path,
    char *ctype, char *rname)
{
	struct ssh_channels *sc = ssh->chanctxt;
	struct permission_set *pset = &sc->local_perms;
	u_int i, permit, permit_adm = 1;
	struct permission *perm;

	permit = pset->all_permitted;
	nếu (!permit) {
		cho (i = 0; i < pset->num_permitted_user; i++) {
			perm = &pset->permitted_user[i];
			nếu (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit = 1;
				break;
			}
		}
	}

	nếu (pset->num_permitted_admin > 0) {
		permit_adm = 0;
		cho (i = 0; i < pset->num_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			nếu (open_match(perm, path, PORT_STREAMLOCAL)) {
				permit_adm = 1;
				break;
			}
		}
	}

	nếu (!permit || !permit_adm) {
		logit("Received request to connect to path %.100s, "
		    "but the request was denied.", path);
		trả_về NULL;
	}
	trả_về connect_to(ssh, path, PORT_STREAMLOCAL, ctype, rname);
}

void
channel_send_window_changes(struct ssh *ssh)
{
	struct ssh_channels *sc = ssh->chanctxt;
	struct winsize ws;
	số_nguyên r;
	u_int i;

	cho (i = 0; i < sc->channels_alloc; i++) {
		nếu (sc->channels[i] == NULL || !sc->channels[i]->client_tty ||
		    sc->channels[i]->type != SSH_CHANNEL_OPEN)
			continue;
		nếu (ioctl(sc->channels[i]->rfd, TIOCGWINSZ, &ws) == -1)
			continue;
		channel_request_start(ssh, i, "window-change", 0);
		nếu ((r = sshpkt_put_u32(ssh, (u_int)ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, (u_int)ws.ws_ypixel)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "channel %u; send window-change", i);
	}
}

/* Return RDYNAMIC_OPEN channel: channel allows SOCKS, but is not connected */
static Channel *
rdynamic_connect_prepare(struct ssh *ssh, char *ctype, char *rname)
{
	Channel *c;
	số_nguyên r;

	c = channel_new(ssh, ctype, SSH_CHANNEL_RDYNAMIC_OPEN, -1, -1, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, rname, 1);
	c->host_port = 0;
	c->path = NULL;

	/*
	 * We need to open the channel before we have a FD,
	 * so that we can get SOCKS header from peer.
	 */
	nếu ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0)
		fatal_fr(r, "channel %i; confirm", c->self);
	trả_về c;
}

/* Return CONNECTING socket to remote host:port or local socket path */
static số_nguyên
rdynamic_connect_finish(struct ssh *ssh, Channel *c)
{
	struct ssh_channels *sc = ssh->chanctxt;
	struct permission_set *pset = &sc->local_perms;
	struct permission *perm;
	struct channel_connect cctx;
	u_int i, permit_adm = 1;
	số_nguyên sock;

	nếu (pset->num_permitted_admin > 0) {
		permit_adm = 0;
		cho (i = 0; i < pset->num_permitted_admin; i++) {
			perm = &pset->permitted_admin[i];
			nếu (open_match(perm, c->path, c->host_port)) {
				permit_adm = 1;
				break;
			}
		}
	}
	nếu (!permit_adm) {
		debug_f("requested forward not permitted");
		trả_về -1;
	}

	memset(&cctx, 0, sizeof(cctx));
	sock = connect_to_helper(ssh, c->path, c->host_port, SOCK_STREAM, NULL,
	    NULL, &cctx, NULL, NULL);
	nếu (sock == -1)
		free_connect_ctx(&cctx);
	không_thì {
		/* similar to SSH_CHANNEL_CONNECTING but we've already sent the open */
		c->type = SSH_CHANNEL_RDYNAMIC_FINISH;
		c->connect_ctx = xmalloc(sizeof(cctx));
		memcpy(c->connect_ctx, &cctx, sizeof(cctx));
		channel_register_fds(ssh, c, sock, sock, -1, 0, 1, 0);
	}
	trả_về sock;
}

/* -- X11 forwarding */

/*
 * Creates an internet domain socket for listening for X11 connections.
 * Returns 0 and a suitable display number for the DISPLAY variable
 * stored in display_numberp , or -1 if an error occurs.
 */
số_nguyên
x11_create_display_inet(struct ssh *ssh, số_nguyên x11_display_offset,
    số_nguyên x11_use_localhost, số_nguyên single_connection,
    u_int *display_numberp, số_nguyên **chanids)
{
	Channel *nc = NULL;
	số_nguyên display_number, sock, port;
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	số_nguyên gaierr, n, num_socks = 0, socks[NUM_SOCKS];

	nếu (chanids == NULL || x11_display_offset < 0 ||
	    x11_display_offset > UINT16_MAX - X11_BASE_PORT - MAX_DISPLAYS)
		trả_về -1;

	cho (display_number = x11_display_offset;
	    display_number < x11_display_offset + MAX_DISPLAYS;
	    display_number++) {
		port = X11_BASE_PORT + display_number;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = ssh->chanctxt->IPv4or6;
		hints.ai_flags = x11_use_localhost ? 0: AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(strport, sizeof strport, "%d", port);
		nếu ((gaierr = getaddrinfo(NULL, strport,
		    &hints, &aitop)) != 0) {
			error("getaddrinfo: %.100s", ssh_gai_strerror(gaierr));
			trả_về -1;
		}
		cho (ai = aitop; ai; ai = ai->ai_next) {
			nếu (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6)
				continue;
			sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			nếu (sock == -1) {
				nếu ((errno != EINVAL) && (errno != EAFNOSUPPORT)
#ifdef EPFNOSUPPORT
				    && (errno != EPFNOSUPPORT)
#endif 
				    ) {
					error("socket: %.100s", strerror(errno));
					freeaddrinfo(aitop);
					trả_về -1;
				} không_thì {
					debug("x11_create_display_inet: Socket family %d not supported",
						 ai->ai_family);
					continue;
				}
			}
			nếu (ai->ai_family == AF_INET6)
				sock_set_v6only(sock);
			nếu (x11_use_localhost)
				set_reuseaddr(sock);
			nếu (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
				debug2_f("bind port %d: %.100s", port,
				    strerror(errno));
				close(sock);
				cho (n = 0; n < num_socks; n++)
					close(socks[n]);
				num_socks = 0;
				break;
			}
			socks[num_socks++] = sock;
			nếu (num_socks == NUM_SOCKS)
				break;
		}
		freeaddrinfo(aitop);
		nếu (num_socks > 0)
			break;
	}
	nếu (display_number >= x11_display_offset + MAX_DISPLAYS) {
		error("Failed to allocate internet-domain X11 display socket.");
		trả_về -1;
	}
	/* Start listening for connections on the socket. */
	cho (n = 0; n < num_socks; n++) {
		sock = socks[n];
		nếu (listen(sock, SSH_LISTEN_BACKLOG) == -1) {
			error("listen: %.100s", strerror(errno));
			close(sock);
			trả_về -1;
		}
	}

	/* Allocate a channel for each socket. */
	*chanids = xcalloc(num_socks + 1, sizeof(**chanids));
	cho (n = 0; n < num_socks; n++) {
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
	trả_về 0;
}

static số_nguyên
connect_local_xsocket_path(const char *pathname)
{
	số_nguyên sock;
	struct sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	nếu (sock == -1) {
		error("socket: %.100s", strerror(errno));
		trả_về -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, pathname, sizeof addr.sun_path);
	nếu (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0)
		trả_về sock;
	close(sock);
	error("connect %.100s: %.100s", addr.sun_path, strerror(errno));
	trả_về -1;
}

static số_nguyên
connect_local_xsocket(u_int dnr)
{
	char buf[1024];
	snprintf(buf, sizeof buf, _PATH_UNIX_X, dnr);
	trả_về connect_local_xsocket_path(buf);
}

#ifdef __APPLE__
static số_nguyên
is_path_to_xsocket(const char *display, char *path, size_t pathlen)
{
	struct stat sbuf;

	nếu (strlcpy(path, display, pathlen) >= pathlen) {
		error_f("display path too long");
		trả_về 0;
	}
	nếu (display[0] != '/')
		trả_về 0;
	nếu (stat(path, &sbuf) == 0) {
		trả_về 1;
	} không_thì {
		char *dot = strrchr(path, '.');
		nếu (dot != NULL) {
			*dot = '\0';
			nếu (stat(path, &sbuf) == 0) {
				trả_về 1;
			}
		}
	}
	trả_về 0;
}
#endif

số_nguyên
x11_connect_display(struct ssh *ssh)
{
	u_int display_number;
	const char *display;
	char buf[1024], *cp;
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	số_nguyên gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	nếu (!display) {
		error("DISPLAY not set.");
		trả_về -1;
	}
	/*
	 * Now we decode the value of the DISPLAY variable and make a
	 * connection to the real X server.
	 */

#ifdef __APPLE__
	/* Check if display is a path to a socket (as set by launchd). */
	{
		char path[PATH_MAX];

		nếu (is_path_to_xsocket(display, path, sizeof(path))) {
			debug("x11_connect_display: $DISPLAY is launchd");

			/* Create a socket. */
			sock = connect_local_xsocket_path(path);
			nếu (sock < 0)
				trả_về -1;

			/* OK, we now have a connection to the display. */
			trả_về sock;
		}
	}
#endif
	/*
	 * Check if it is a unix domain socket.  Unix domain displays are in
	 * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
	 */
	nếu (strncmp(display, "unix:", 5) == 0 ||
	    display[0] == ':') {
		/* Connect to the unix domain socket. */
		nếu (sscanf(strrchr(display, ':') + 1, "%u",
		    &display_number) != 1) {
			error("Could not parse display number from DISPLAY: "
			    "%.100s", display);
			trả_về -1;
		}
		/* Create a socket. */
		sock = connect_local_xsocket(display_number);
		nếu (sock < 0)
			trả_về -1;

		/* OK, we now have a connection to the display. */
		trả_về sock;
	}
	/*
	 * Connect to an inet socket.  The DISPLAY value is supposedly
	 * hostname:d[.s], where hostname may also be numeric IP address.
	 */
	strlcpy(buf, display, sizeof(buf));
	cp = strchr(buf, ':');
	nếu (!cp) {
		error("Could not find ':' in DISPLAY: %.100s", display);
		trả_về -1;
	}
	*cp = 0;
	/*
	 * buf now contains the host name.  But first we parse the
	 * display number.
	 */
	nếu (sscanf(cp + 1, "%u", &display_number) != 1 ||
	    display_number > UINT16_MAX - X11_BASE_PORT) {
		error("Could not parse display number from DISPLAY: %.100s",
		    display);
		trả_về -1;
	}

	/* Look up the host address */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ssh->chanctxt->IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, sizeof strport, "%u", X11_BASE_PORT + display_number);
	nếu ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		error("%.100s: unknown host. (%s)", buf,
		ssh_gai_strerror(gaierr));
		trả_về -1;
	}
	cho (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		nếu (sock == -1) {
			debug2("socket: %.100s", strerror(errno));
			continue;
		}
		/* Connect it to the display. */
		nếu (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			debug2("connect %.100s port %u: %.100s", buf,
			    X11_BASE_PORT + display_number, strerror(errno));
			close(sock);
			continue;
		}
		/* Success */
		break;
	}
	freeaddrinfo(aitop);
	nếu (!ai) {
		error("connect %.100s port %u: %.100s", buf,
		    X11_BASE_PORT + display_number, strerror(errno));
		trả_về -1;
	}
	set_nodelay(sock);
	trả_về sock;
}

/*
 * Requests forwarding of X11 connections, generates fake authentication
 * data, and enables authentication spoofing.
 * This should be called in the client only.
 */
void
x11_request_forwarding_with_spoofing(struct ssh *ssh, số_nguyên client_session_id,
    const char *disp, const char *proto, const char *data, số_nguyên want_reply)
{
	struct ssh_channels *sc = ssh->chanctxt;
	u_int data_len = (u_int) strlen(data) / 2;
	u_int i, value;
	const char *cp;
	char *new_data;
	số_nguyên r, screen_number;

	nếu (sc->x11_saved_display == NULL)
		sc->x11_saved_display = xstrdup(disp);
	không_thì nếu (strcmp(disp, sc->x11_saved_display) != 0) {
		error("x11_request_forwarding_with_spoofing: different "
		    "$DISPLAY already forwarded");
		trả_về;
	}

	cp = strchr(disp, ':');
	nếu (cp)
		cp = strchr(cp, '.');
	nếu (cp)
		screen_number = (u_int)strtonum(cp + 1, 0, 400, NULL);
	không_thì
		screen_number = 0;

	nếu (sc->x11_saved_proto == NULL) {
		/* Save protocol name. */
		sc->x11_saved_proto = xstrdup(proto);

		/* Extract real authentication data. */
		sc->x11_saved_data = xmalloc(data_len);
		cho (i = 0; i < data_len; i++) {
			nếu (sscanf(data + 2 * i, "%2x", &value) != 1) {
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
	nếu ((r = sshpkt_put_u8(ssh, 0)) != 0 || /* bool: single connection */
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
số_nguyên
x11_channel_used_recently(struct ssh *ssh) {
	u_int i;
	Channel *c;
	double lastused = 0;

	cho (i = 0; i < ssh->chanctxt->channels_alloc; i++) {
		c = ssh->chanctxt->channels[i];
		nếu (c == NULL || c->ctype == NULL || c->lastused == 0.0 ||
		    strcmp(c->ctype, "x11-connection") != 0)
			continue;
		nếu (c->lastused > lastused)
			lastused = c->lastused;
	}
	trả_về lastused != 0.0 && monotime_double() <= lastused + 1.0;
}
