/* $OpenBSD: channels.h,v 1.171 2026/09/16 23:26:41 jsg Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright (c) 1999, 2000, 2001, 2002 Markus Friedl.  All rights reserved.
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

#ifndef CHANNEL_H
#define CHANNEL_H

/* Definitions for channel types. */
#define SSH_CHANNEL_X11_LISTENER	1	/* Listening for inet X11 conn. */
#define SSH_CHANNEL_PORT_LISTENER	2	/* Listening on a port. */
#define SSH_CHANNEL_OPENING		3	/* waiting for confirmation */
#define SSH_CHANNEL_OPEN		4	/* normal open two-way channel */
#define SSH_CHANNEL_CLOSED		5	/* waiting for close confirmation */
#define SSH_CHANNEL_AUTH_SOCKET		6	/* authentication socket */
#define SSH_CHANNEL_X11_OPEN		7	/* reading first X11 packet */
#define SSH_CHANNEL_LARVAL		10	/* larval session */
#define SSH_CHANNEL_RPORT_LISTENER	11	/* Listening to a R-style port  */
#define SSH_CHANNEL_CONNECTING		12
#define SSH_CHANNEL_DYNAMIC		13
#define SSH_CHANNEL_ZOMBIE		14	/* Almost dead. */
#define SSH_CHANNEL_MUX_LISTENER	15	/* Listener for mux conn. */
#define SSH_CHANNEL_MUX_CLIENT		16	/* Conn. to mux client */
#define SSH_CHANNEL_ABANDONED		17	/* Abandoned session, eg mux */
#define SSH_CHANNEL_UNIX_LISTENER	18	/* Listening on a domain socket. */
#define SSH_CHANNEL_RUNIX_LISTENER	19	/* Listening to a R-style domain socket. */
#define SSH_CHANNEL_MUX_PROXY		20	/* proxy channel for mux-client */
#define SSH_CHANNEL_RDYNAMIC_OPEN	21	/* reverse SOCKS, parsing request */
#define SSH_CHANNEL_RDYNAMIC_FINISH	22	/* reverse SOCKS, finishing connect */
#define SSH_CHANNEL_MAX_TYPE		23

#define CHANNEL_CANCEL_PORT_STATIC	-1

/* nonblocking flags for channel_new */
#define CHANNEL_NONBLOCK_LEAVE	0 /* don't modify non-blocking state */
#define CHANNEL_NONBLOCK_SET	1 /* set non-blocking state */
#define CHANNEL_NONBLOCK_STDIO	2 /* set non-blocking and restore on close */

/* c->restore_block mask flags */
#define CHANNEL_RESTORE_RFD	0x01
#define CHANNEL_RESTORE_WFD	0x02
#define CHANNEL_RESTORE_EFD	0x04

/* TCP forwarding */
#define FORWARD_DENY		0
#define FORWARD_REMOTE		(1)
#define FORWARD_LOCAL		(1<<1)
#define FORWARD_ALLOW		(FORWARD_REMOTE|FORWARD_LOCAL)

#define FORWARD_ADM		0x100
#define FORWARD_USER		0x101

/* default pattern-lists used to classify channel types as bulk */
#define CHANNEL_BULK_TTY	""
#define CHANNEL_BULK_NOTTY	"direct-*,forwarded-*,dynamic-*," \
				"tun-*,x11-*,session*,stdio-forward"

ಸಂರಚನಾ ssh;
ಸಂರಚನಾ Channel;
ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ Channel Channel;
ಸಂರಚನಾ channel_connect;

ಪ್ರಕಾರನಿರ್ದೇಶ ಶೂನ್ಯ channel_open_fn(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಶೂನ್ಯ *);
ಪ್ರಕಾರನಿರ್ದೇಶ ಶೂನ್ಯ channel_callback_fn(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಶೂನ್ಯ *);
ಪ್ರಕಾರನಿರ್ದೇಶ ಪೂರ್ಣಾಙ್ಕ channel_infilter_fn(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ Channel *, ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
ಪ್ರಕಾರನಿರ್ದೇಶ ಶೂನ್ಯ channel_filter_cleanup_fn(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಶೂನ್ಯ *);
ಪ್ರಕಾರನಿರ್ದೇಶ u_char *channel_outfilter_fn(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ Channel *,
    u_char **, size_t *);

/* Channel success/failure callbacks */
ಪ್ರಕಾರನಿರ್ದೇಶ ಶೂನ್ಯ channel_confirm_cb(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ Channel *, ಶೂನ್ಯ *);
ಪ್ರಕಾರನಿರ್ದೇಶ ಶೂನ್ಯ channel_confirm_abandon_cb(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ Channel *, ಶೂನ್ಯ *);
ಸಂರಚನಾ channel_confirm {
	TAILQ_ENTRY(channel_confirm) entry;
	channel_confirm_cb *cb;
	channel_confirm_abandon_cb *abandon_cb;
	ಶೂನ್ಯ *ctx;
};
TAILQ_HEAD(channel_confirms, channel_confirm);

/* Callbacks for mux channels back into client-specific code */
ಪ್ರಕಾರನಿರ್ದೇಶ ಪೂರ್ಣಾಙ್ಕ mux_callback_fn(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ Channel *);

/*
 * NB. channel IDs on the wire and in c->remote_id are uint32, but local
 * channel IDs (e.g. c->self) only ever use the int32 subset of this range,
 * because we use local channel ID -1 for housekeeping. Remote channels have
 * a dedicated "have_remote_id" flag to indicate their validity.
 */

ಸಂರಚನಾ Channel {
	ಪೂರ್ಣಾಙ್ಕ     type;		/* channel type/state */

	ಪೂರ್ಣಾಙ್ಕ     self;		/* my own channel identifier */
	uint32_t remote_id;	/* channel identifier for remote peer */
	ಪೂರ್ಣಾಙ್ಕ	have_remote_id;	/* non-zero if remote_id is valid */

	u_int   istate;		/* input from channel (state of receive half) */
	u_int   ostate;		/* output to channel  (state of transmit half) */
	ಪೂರ್ಣಾಙ್ಕ     flags;		/* close sent/rcvd */
	ಪೂರ್ಣಾಙ್ಕ     rfd;		/* read fd */
	ಪೂರ್ಣಾಙ್ಕ     wfd;		/* write fd */
	ಪೂರ್ಣಾಙ್ಕ     efd;		/* extended fd */
	ಪೂರ್ಣಾಙ್ಕ     sock;		/* sock fd */
	u_int	io_want;	/* bitmask of SSH_CHAN_IO_* */
	u_int	io_ready;	/* bitmask of SSH_CHAN_IO_* */
	ಪೂರ್ಣಾಙ್ಕ	pfds[4];	/* pollfd entries for rfd/wfd/efd/sock */
	ಪೂರ್ಣಾಙ್ಕ     ctl_chan;	/* control channel (multiplexed connections) */
	uint32_t ctl_child_id;	/* child session for mux controllers */
	ಪೂರ್ಣಾಙ್ಕ	have_ctl_child_id;/* non-zero if ctl_child_id is valid */
	ಪೂರ್ಣಾಙ್ಕ     remote_has_tty;	/* remote side has a tty */
	ಪೂರ್ಣಾಙ್ಕ     isatty;		/* rfd is a tty */
#ifdef _AIX
	ಪೂರ್ಣಾಙ್ಕ     wfd_isatty;	/* wfd is a tty */
#endif
	ಪೂರ್ಣಾಙ್ಕ	client_tty;	/* (client) TTY has been requested */
	ಪೂರ್ಣಾಙ್ಕ     force_drain;	/* force close on iEOF */
	ದ್ವಿಗುಣ	notbefore;	/* Pause IO until deadline (time_t) */
	ಪೂರ್ಣಾಙ್ಕ     delayed;	/* post-IO handlers for newly created
				 * channels are delayed until the first call
				 * to a matching pre-IO handler.
				 * this way post-IO handlers are not
				 * accidentally called if a FD gets reused */
	ಪೂರ್ಣಾಙ್ಕ	restore_block;	/* fd mask to restore blocking status */
	ಪೂರ್ಣಾಙ್ಕ	restore_flags[3];/* flags to restore */
	ಸಂರಚನಾ sshbuf *ಒಳಹರಿವು;	/* data read from socket, to be sent over
				 * encrypted connection */
	ಸಂರಚನಾ sshbuf *output;	/* data received over encrypted connection for
				 * send on socket */
	ಸಂರಚನಾ sshbuf *extended;

	ವರ್ಣ    *path;
		/* path for unix domain sockets, or host name for forwards */
	ಪೂರ್ಣಾಙ್ಕ     listening_port;	/* port being listened for forwards */
	ವರ್ಣ   *listening_addr;	/* addr being listened for forwards */
	ಪೂರ್ಣಾಙ್ಕ     host_port;	/* remote port to connect for forwards */
	ವರ್ಣ   *remote_name;	/* remote hostname */

	u_int	remote_window;
	u_int	remote_maxpacket;
	u_int	local_window;
	u_int	local_window_exceeded;
	u_int	local_window_max;
	u_int	local_consumed;
	u_int	local_maxpacket;
	ಪೂರ್ಣಾಙ್ಕ     extended_usage;
	ಪೂರ್ಣಾಙ್ಕ	agent_new;	/* For agent listeners, use RFC 9987 requests */
	ಪೂರ್ಣಾಙ್ಕ	single_connection;

	ವರ್ಣ   *ctype;		/* const type - NB. not freed on channel_free */
	ವರ್ಣ   *xctype;		/* extended type */
	ಪೂರ್ಣಾಙ್ಕ	bulk;		/* channel is non-interactive */

	/* callback */
	channel_open_fn		*open_confirm;
	ಶೂನ್ಯ			*open_confirm_ctx;
	channel_callback_fn	*detach_user;
	ಪೂರ್ಣಾಙ್ಕ			detach_close;
	ಸಂರಚನಾ channel_confirms	status_confirms;

	/* filter */
	channel_infilter_fn	*ಒಳಹರಿವು_filter;
	channel_outfilter_fn	*output_filter;
	ಶೂನ್ಯ			*filter_ctx;
	channel_filter_cleanup_fn *filter_cleanup;

	/* keep boundaries */
	ಪೂರ್ಣಾಙ್ಕ			datagram;

	/* non-blocking connect */
	ಸಂರಚನಾ channel_connect	*connect_ctx;

	/* multiplexing protocol hook, called for each packet received */
	mux_callback_fn		*mux_rcb;
	ಶೂನ್ಯ			*mux_ctx;
	ಪೂರ್ಣಾಙ್ಕ			mux_pause;
	ಪೂರ್ಣಾಙ್ಕ			mux_downstream_id;

	/* Inactivity timeouts */

	/* Last traffic seen for OPEN channels */
	ದ್ವಿಗುಣ			lastused;
	/* Inactivity timeout deadline in seconds (0 = no timeout) */
	ದ್ವಿಗುಣ			inactive_deadline;
};

#define CHAN_EXTENDED_IGNORE		0
#define CHAN_EXTENDED_READ		1
#define CHAN_EXTENDED_WRITE		2

/* default window/packet sizes for tcp/x11-fwd-channel */
#define CHAN_SES_PACKET_DEFAULT	(32*1024)
#define CHAN_SES_WINDOW_DEFAULT	(64*CHAN_SES_PACKET_DEFAULT)
#define CHAN_TCP_PACKET_DEFAULT	(32*1024)
#define CHAN_TCP_WINDOW_DEFAULT	(64*CHAN_TCP_PACKET_DEFAULT)
#define CHAN_X11_PACKET_DEFAULT	(16*1024)
#define CHAN_X11_WINDOW_DEFAULT	(4*CHAN_X11_PACKET_DEFAULT)

/* possible input states */
#define CHAN_ಒಳಹರಿವು_OPEN			0
#define CHAN_ಒಳಹರಿವು_WAIT_DRAIN		1
#define CHAN_ಒಳಹರಿವು_WAIT_OCLOSE		2
#define CHAN_ಒಳಹರಿವು_CLOSED		3

/* possible output states */
#define CHAN_OUTPUT_OPEN		0
#define CHAN_OUTPUT_WAIT_DRAIN		1
#define CHAN_OUTPUT_WAIT_IEOF		2
#define CHAN_OUTPUT_CLOSED		3

#define CHAN_CLOSE_SENT			0x01
#define CHAN_CLOSE_RCVD			0x02
#define CHAN_EOF_SENT			0x04
#define CHAN_EOF_RCVD			0x08
#define CHAN_LOCAL			0x10

/* file descriptor events */
#define SSH_CHAN_IO_RFD			0x01
#define SSH_CHAN_IO_WFD			0x02
#define SSH_CHAN_IO_EFD_R		0x04
#define SSH_CHAN_IO_EFD_W		0x08
#define SSH_CHAN_IO_EFD			(SSH_CHAN_IO_EFD_R|SSH_CHAN_IO_EFD_W)
#define SSH_CHAN_IO_SOCK_R		0x10
#define SSH_CHAN_IO_SOCK_W		0x20
#define SSH_CHAN_IO_SOCK		(SSH_CHAN_IO_SOCK_R|SSH_CHAN_IO_SOCK_W)

/* Read buffer size */
#define CHAN_RBUF	(16*1024)

/* Maximum size for direct reads to buffers */
#define CHANNEL_MAX_READ	CHAN_SES_PACKET_DEFAULT

/* Maximum channel input buffer size */
#define CHAN_ಒಳಹರಿವು_MAX	(16*1024*1024)

/* Hard limit on number of channels */
#define CHANNELS_MAX_CHANNELS	(16*1024)

/* check whether 'efd' is still in use */
#define CHANNEL_EFD_ಒಳಹರಿವು_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_READ && \
	(c->efd != -1 || \
	sshbuf_len(c->extended) > 0))
#define CHANNEL_EFD_OUTPUT_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_WRITE && \
	c->efd != -1 && (!(c->flags & (CHAN_EOF_RCVD|CHAN_CLOSE_RCVD)) || \
	sshbuf_len(c->extended) > 0))

/* Add/remove channel management structures to/from SSH transport instance */
ಶೂನ್ಯ channel_init_channels(ಸಂರಚನಾ ssh *ssh);
ಶೂನ್ಯ channel_free_channels(ಸಂರಚನಾ ssh *ssh);

/* channel management */

Channel	*channel_by_id(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);
Channel	*channel_by_remote_id(ಸಂರಚನಾ ssh *, u_int);
Channel	*channel_lookup(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);
Channel *channel_new(ಸಂರಚನಾ ssh *, ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ,
	    u_int, u_int, ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 channel_set_fds(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ,
	    ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, u_int);
ಶೂನ್ಯ	 channel_set_tty(ಸಂರಚನಾ ssh *, Channel *);
ಶೂನ್ಯ	 channel_free(ಸಂರಚನಾ ssh *, Channel *);
ಶೂನ್ಯ	 channel_free_all(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ	 channel_stop_listening(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ	 channel_force_close(ಸಂರಚನಾ ssh *, Channel *, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 channel_set_xtype(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *);

ಶೂನ್ಯ	 channel_send_open(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 channel_request_start(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 channel_register_cleanup(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ,
	    channel_callback_fn *, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 channel_register_open_confirm(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ,
	    channel_open_fn *, ಶೂನ್ಯ *);
ಶೂನ್ಯ	 channel_register_filter(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, channel_infilter_fn *,
	    channel_outfilter_fn *, channel_filter_cleanup_fn *, ಶೂನ್ಯ *);
ಶೂನ್ಯ	 channel_register_status_confirm(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ,
	    channel_confirm_cb *, channel_confirm_abandon_cb *, ಶೂನ್ಯ *);
ಶೂನ್ಯ	 channel_cancel_cleanup(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 channel_close_fd(ಸಂರಚನಾ ssh *, Channel *, ಪೂರ್ಣಾಙ್ಕ *);
ಶೂನ್ಯ	 channel_send_window_changes(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 channel_has_bulk(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ	 channel_set_tcp_keepalives(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);

/* channel inactivity timeouts */
ಶೂನ್ಯ channel_add_timeout(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *, ದ್ವಿಗುಣ);
ಶೂನ್ಯ channel_clear_timeouts(ಸಂರಚನಾ ssh *);

/* mux proxy support */

ಪೂರ್ಣಾಙ್ಕ	 channel_proxy_downstream(ಸಂರಚನಾ ssh *, Channel *mc);
ಪೂರ್ಣಾಙ್ಕ	 channel_proxy_upstream(Channel *, ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);

/* protocol handler */

ಪೂರ್ಣಾಙ್ಕ	 channel_ಒಳಹರಿವು_data(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 channel_ಒಳಹರಿವು_extended_data(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 channel_ಒಳಹರಿವು_ieof(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 channel_ಒಳಹರಿವು_oclose(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 channel_ಒಳಹರಿವು_open_confirmation(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 channel_ಒಳಹರಿವು_open_failure(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 channel_ಒಳಹರಿವು_window_adjust(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 channel_ಒಳಹರಿವು_status_confirm(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);

/* file descriptor handling (read/write) */
ಸಂರಚನಾ pollfd;
ಸಂರಚನಾ timespec;

ಶೂನ್ಯ	 channel_prepare_poll(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ pollfd **,
	    u_int *, u_int *, u_int, ಸಂರಚನಾ timespec *);
ಶೂನ್ಯ	 channel_after_poll(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ pollfd *, u_int);
ಪೂರ್ಣಾಙ್ಕ	 channel_output_poll(ಸಂರಚನಾ ssh *);

ಪೂರ್ಣಾಙ್ಕ      channel_not_very_much_buffered_data(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ     channel_close_all(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ      channel_still_open(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 channel_tty_open(ಸಂರಚನಾ ssh *);
ಧ್ರುವ ವರ್ಣ *channel_format_extended_usage(ಧ್ರುವ Channel *);
ವರ್ಣ	*channel_open_message(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ	 channel_report_open(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 channel_find_open(ಸಂರಚನಾ ssh *);

/* tcp forwarding */
ಸಂರಚನಾ Forward;
ಸಂರಚನಾ ForwardOptions;
ಶೂನ್ಯ	 channel_set_af(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ af);
ಶೂನ್ಯ     channel_permit_all(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 channel_add_permission(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 channel_clear_permission(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 channel_disable_admin(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 channel_update_permission(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
Channel	*channel_connect_to_port(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *, u_short,
	    ವರ್ಣ *, ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ *, ಧ್ರುವ ವರ್ಣ **);
Channel *channel_connect_to_path(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *, ವರ್ಣ *, ವರ್ಣ *);
Channel	*channel_connect_stdio_fwd(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ*,
	    ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
Channel	*channel_connect_by_listen_address(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *,
	    u_short, ವರ್ಣ *, ವರ್ಣ *);
Channel	*channel_connect_by_listen_path(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *,
	    ವರ್ಣ *, ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 channel_request_remote_forwarding(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ Forward *);
ಪೂರ್ಣಾಙ್ಕ	 channel_setup_local_fwd_listener(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ Forward *,
	    ಸಂರಚನಾ ForwardOptions *);
ಪೂರ್ಣಾಙ್ಕ	 channel_request_rforward_cancel(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ Forward *);
ಪೂರ್ಣಾಙ್ಕ	 channel_setup_remote_fwd_listener(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ Forward *,
	    ಪೂರ್ಣಾಙ್ಕ *, ಸಂರಚನಾ ForwardOptions *);
ಪೂರ್ಣಾಙ್ಕ	 channel_cancel_rport_listener(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ Forward *);
ಪೂರ್ಣಾಙ್ಕ	 channel_cancel_lport_listener(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ Forward *,
	    ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ ForwardOptions *);
ಪೂರ್ಣಾಙ್ಕ	 permitopen_port(ಧ್ರುವ ವರ್ಣ *);

/* x11 forwarding */

ಶೂನ್ಯ	 channel_set_x11_refuse_time(ಸಂರಚನಾ ssh *, ದ್ವಿಗುಣ);
ಪೂರ್ಣಾಙ್ಕ	 x11_connect_display(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 x11_create_display_inet(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, u_int *, ಪೂರ್ಣಾಙ್ಕ **);
ಶೂನ್ಯ	 x11_request_forwarding_with_spoofing(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ,
	    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ      x11_channel_used_recently(ಸಂರಚನಾ ssh *ssh);

/* channel close */

ಪೂರ್ಣಾಙ್ಕ	 chan_is_dead(ಸಂರಚನಾ ssh *, Channel *, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 chan_mark_dead(ಸಂರಚನಾ ssh *, Channel *);

/* agent forwarding */
ಶೂನ್ಯ	 client_channel_request_agent_forwarding(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);

/* channel events */

ಶೂನ್ಯ	 chan_rcvd_oclose(ಸಂರಚನಾ ssh *, Channel *);
ಶೂನ್ಯ	 chan_rcvd_eow(ಸಂರಚನಾ ssh *, Channel *);
ಶೂನ್ಯ	 chan_read_failed(ಸಂರಚನಾ ssh *, Channel *);
ಶೂನ್ಯ	 chan_ibuf_empty(ಸಂರಚನಾ ssh *, Channel *);
ಶೂನ್ಯ	 chan_rcvd_ieof(ಸಂರಚನಾ ssh *, Channel *);
ಶೂನ್ಯ	 chan_write_failed(ಸಂರಚನಾ ssh *, Channel *);
ಶೂನ್ಯ	 chan_obuf_empty(ಸಂರಚನಾ ssh *, Channel *);

#endif
