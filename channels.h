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

ساختار ssh;
ساختار Channel;
تعریفنوع ساختار Channel Channel;
ساختار channel_connect;

تعریفنوع تهی channel_open_fn(ساختار ssh *, صحیح, صحیح, تهی *);
تعریفنوع تهی channel_callback_fn(ساختار ssh *, صحیح, صحیح, تهی *);
تعریفنوع صحیح channel_infilter_fn(ساختار ssh *, ساختار Channel *, نویسه *, صحیح);
تعریفنوع تهی channel_filter_cleanup_fn(ساختار ssh *, صحیح, تهی *);
تعریفنوع u_char *channel_outfilter_fn(ساختار ssh *, ساختار Channel *,
    u_char **, size_t *);

/* Channel success/failure callbacks */
تعریفنوع تهی channel_confirm_cb(ساختار ssh *, صحیح, ساختار Channel *, تهی *);
تعریفنوع تهی channel_confirm_abandon_cb(ساختار ssh *, ساختار Channel *, تهی *);
ساختار channel_confirm {
	TAILQ_ENTRY(channel_confirm) entry;
	channel_confirm_cb *cb;
	channel_confirm_abandon_cb *abandon_cb;
	تهی *ctx;
};
TAILQ_HEAD(channel_confirms, channel_confirm);

/* Callbacks for mux channels back into client-specific code */
تعریفنوع صحیح mux_callback_fn(ساختار ssh *, ساختار Channel *);

/*
 * NB. channel IDs on the wire and in c->remote_id are uint32, but local
 * channel IDs (e.g. c->self) only ever use the int32 subset of this range,
 * because we use local channel ID -1 for housekeeping. Remote channels have
 * a dedicated "have_remote_id" flag to indicate their validity.
 */

ساختار Channel {
	صحیح     type;		/* channel type/state */

	صحیح     self;		/* my own channel identifier */
	uint32_t remote_id;	/* channel identifier for remote peer */
	صحیح	have_remote_id;	/* non-zero if remote_id is valid */

	u_int   istate;		/* input from channel (state of receive half) */
	u_int   ostate;		/* output to channel  (state of transmit half) */
	صحیح     flags;		/* close sent/rcvd */
	صحیح     rfd;		/* read fd */
	صحیح     wfd;		/* write fd */
	صحیح     efd;		/* extended fd */
	صحیح     sock;		/* sock fd */
	u_int	io_want;	/* bitmask of SSH_CHAN_IO_* */
	u_int	io_ready;	/* bitmask of SSH_CHAN_IO_* */
	صحیح	pfds[4];	/* pollfd entries for rfd/wfd/efd/sock */
	صحیح     ctl_chan;	/* control channel (multiplexed connections) */
	uint32_t ctl_child_id;	/* child session for mux controllers */
	صحیح	have_ctl_child_id;/* non-zero if ctl_child_id is valid */
	صحیح     remote_has_tty;	/* remote side has a tty */
	صحیح     isatty;		/* rfd is a tty */
#ifdef _AIX
	صحیح     wfd_isatty;	/* wfd is a tty */
#endif
	صحیح	client_tty;	/* (client) TTY has been requested */
	صحیح     force_drain;	/* force close on iEOF */
	دوگانه	notbefore;	/* Pause IO until deadline (time_t) */
	صحیح     delayed;	/* post-IO handlers for newly created
				 * channels are delayed until the first call
				 * to a matching pre-IO handler.
				 * this way post-IO handlers are not
				 * accidentally called if a FD gets reused */
	صحیح	restore_block;	/* fd mask to restore blocking status */
	صحیح	restore_flags[3];/* flags to restore */
	ساختار sshbuf *درون_داد;	/* data read from socket, to be sent over
				 * encrypted connection */
	ساختار sshbuf *output;	/* data received over encrypted connection for
				 * send on socket */
	ساختار sshbuf *extended;

	نویسه    *path;
		/* path for unix domain sockets, or host name for forwards */
	صحیح     listening_port;	/* port being listened for forwards */
	نویسه   *listening_addr;	/* addr being listened for forwards */
	صحیح     host_port;	/* remote port to connect for forwards */
	نویسه   *remote_name;	/* remote hostname */

	u_int	remote_window;
	u_int	remote_maxpacket;
	u_int	local_window;
	u_int	local_window_exceeded;
	u_int	local_window_max;
	u_int	local_consumed;
	u_int	local_maxpacket;
	صحیح     extended_usage;
	صحیح	agent_new;	/* For agent listeners, use RFC 9987 requests */
	صحیح	single_connection;

	نویسه   *ctype;		/* const type - NB. not freed on channel_free */
	نویسه   *xctype;		/* extended type */
	صحیح	bulk;		/* channel is non-interactive */

	/* callback */
	channel_open_fn		*open_confirm;
	تهی			*open_confirm_ctx;
	channel_callback_fn	*detach_user;
	صحیح			detach_close;
	ساختار channel_confirms	status_confirms;

	/* filter */
	channel_infilter_fn	*درون_داد_filter;
	channel_outfilter_fn	*output_filter;
	تهی			*filter_ctx;
	channel_filter_cleanup_fn *filter_cleanup;

	/* keep boundaries */
	صحیح			datagram;

	/* non-blocking connect */
	ساختار channel_connect	*connect_ctx;

	/* multiplexing protocol hook, called for each packet received */
	mux_callback_fn		*mux_rcb;
	تهی			*mux_ctx;
	صحیح			mux_pause;
	صحیح			mux_downstream_id;

	/* Inactivity timeouts */

	/* Last traffic seen for OPEN channels */
	دوگانه			lastused;
	/* Inactivity timeout deadline in seconds (0 = no timeout) */
	دوگانه			inactive_deadline;
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
#define CHAN_درون_داد_OPEN			0
#define CHAN_درون_داد_WAIT_DRAIN		1
#define CHAN_درون_داد_WAIT_OCLOSE		2
#define CHAN_درون_داد_CLOSED		3

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
#define CHAN_درون_داد_MAX	(16*1024*1024)

/* Hard limit on number of channels */
#define CHANNELS_MAX_CHANNELS	(16*1024)

/* check whether 'efd' is still in use */
#define CHANNEL_EFD_درون_داد_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_READ && \
	(c->efd != -1 || \
	sshbuf_len(c->extended) > 0))
#define CHANNEL_EFD_OUTPUT_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_WRITE && \
	c->efd != -1 && (!(c->flags & (CHAN_EOF_RCVD|CHAN_CLOSE_RCVD)) || \
	sshbuf_len(c->extended) > 0))

/* Add/remove channel management structures to/from SSH transport instance */
تهی channel_init_channels(ساختار ssh *ssh);
تهی channel_free_channels(ساختار ssh *ssh);

/* channel management */

Channel	*channel_by_id(ساختار ssh *, صحیح);
Channel	*channel_by_remote_id(ساختار ssh *, u_int);
Channel	*channel_lookup(ساختار ssh *, صحیح);
Channel *channel_new(ساختار ssh *, نویسه *, صحیح, صحیح, صحیح, صحیح,
	    u_int, u_int, صحیح, ثابت نویسه *, صحیح);
تهی	 channel_set_fds(ساختار ssh *, صحیح, صحیح, صحیح, صحیح, صحیح,
	    صحیح, صحیح, u_int);
تهی	 channel_set_tty(ساختار ssh *, Channel *);
تهی	 channel_free(ساختار ssh *, Channel *);
تهی	 channel_free_all(ساختار ssh *);
تهی	 channel_stop_listening(ساختار ssh *);
تهی	 channel_force_close(ساختار ssh *, Channel *, صحیح);
تهی	 channel_set_xtype(ساختار ssh *, صحیح, ثابت نویسه *);

تهی	 channel_send_open(ساختار ssh *, صحیح);
تهی	 channel_request_start(ساختار ssh *, صحیح, ثابت نویسه *, صحیح);
تهی	 channel_register_cleanup(ساختار ssh *, صحیح,
	    channel_callback_fn *, صحیح);
تهی	 channel_register_open_confirm(ساختار ssh *, صحیح,
	    channel_open_fn *, تهی *);
تهی	 channel_register_filter(ساختار ssh *, صحیح, channel_infilter_fn *,
	    channel_outfilter_fn *, channel_filter_cleanup_fn *, تهی *);
تهی	 channel_register_status_confirm(ساختار ssh *, صحیح,
	    channel_confirm_cb *, channel_confirm_abandon_cb *, تهی *);
تهی	 channel_cancel_cleanup(ساختار ssh *, صحیح);
صحیح	 channel_close_fd(ساختار ssh *, Channel *, صحیح *);
تهی	 channel_send_window_changes(ساختار ssh *);
صحیح	 channel_has_bulk(ساختار ssh *);
تهی	 channel_set_tcp_keepalives(ساختار ssh *, صحیح);

/* channel inactivity timeouts */
تهی channel_add_timeout(ساختار ssh *, ثابت نویسه *, دوگانه);
تهی channel_clear_timeouts(ساختار ssh *);

/* mux proxy support */

صحیح	 channel_proxy_downstream(ساختار ssh *, Channel *mc);
صحیح	 channel_proxy_upstream(Channel *, صحیح, uint32_t, ساختار ssh *);

/* protocol handler */

صحیح	 channel_درون_داد_data(صحیح, uint32_t, ساختار ssh *);
صحیح	 channel_درون_داد_extended_data(صحیح, uint32_t, ساختار ssh *);
صحیح	 channel_درون_داد_ieof(صحیح, uint32_t, ساختار ssh *);
صحیح	 channel_درون_داد_oclose(صحیح, uint32_t, ساختار ssh *);
صحیح	 channel_درون_داد_open_confirmation(صحیح, uint32_t, ساختار ssh *);
صحیح	 channel_درون_داد_open_failure(صحیح, uint32_t, ساختار ssh *);
صحیح	 channel_درون_داد_window_adjust(صحیح, uint32_t, ساختار ssh *);
صحیح	 channel_درون_داد_status_confirm(صحیح, uint32_t, ساختار ssh *);

/* file descriptor handling (read/write) */
ساختار pollfd;
ساختار timespec;

تهی	 channel_prepare_poll(ساختار ssh *, ساختار pollfd **,
	    u_int *, u_int *, u_int, ساختار timespec *);
تهی	 channel_after_poll(ساختار ssh *, ساختار pollfd *, u_int);
صحیح	 channel_output_poll(ساختار ssh *);

صحیح      channel_not_very_much_buffered_data(ساختار ssh *);
تهی     channel_close_all(ساختار ssh *);
صحیح      channel_still_open(ساختار ssh *);
صحیح	 channel_tty_open(ساختار ssh *);
ثابت نویسه *channel_format_extended_usage(ثابت Channel *);
نویسه	*channel_open_message(ساختار ssh *);
تهی	 channel_report_open(ساختار ssh *, صحیح);
صحیح	 channel_find_open(ساختار ssh *);

/* tcp forwarding */
ساختار Forward;
ساختار ForwardOptions;
تهی	 channel_set_af(ساختار ssh *, صحیح af);
تهی     channel_permit_all(ساختار ssh *, صحیح);
تهی	 channel_add_permission(ساختار ssh *, صحیح, صحیح, نویسه *, صحیح);
تهی	 channel_clear_permission(ساختار ssh *, صحیح, صحیح);
تهی	 channel_disable_admin(ساختار ssh *, صحیح);
تهی	 channel_update_permission(ساختار ssh *, صحیح, صحیح);
Channel	*channel_connect_to_port(ساختار ssh *, ثابت نویسه *, u_short,
	    نویسه *, نویسه *, صحیح *, ثابت نویسه **);
Channel *channel_connect_to_path(ساختار ssh *, ثابت نویسه *, نویسه *, نویسه *);
Channel	*channel_connect_stdio_fwd(ساختار ssh *, ثابت نویسه*,
	    صحیح, صحیح, صحیح, صحیح);
Channel	*channel_connect_by_listen_address(ساختار ssh *, ثابت نویسه *,
	    u_short, نویسه *, نویسه *);
Channel	*channel_connect_by_listen_path(ساختار ssh *, ثابت نویسه *,
	    نویسه *, نویسه *);
صحیح	 channel_request_remote_forwarding(ساختار ssh *, ساختار Forward *);
صحیح	 channel_setup_local_fwd_listener(ساختار ssh *, ساختار Forward *,
	    ساختار ForwardOptions *);
صحیح	 channel_request_rforward_cancel(ساختار ssh *, ساختار Forward *);
صحیح	 channel_setup_remote_fwd_listener(ساختار ssh *, ساختار Forward *,
	    صحیح *, ساختار ForwardOptions *);
صحیح	 channel_cancel_rport_listener(ساختار ssh *, ساختار Forward *);
صحیح	 channel_cancel_lport_listener(ساختار ssh *, ساختار Forward *,
	    صحیح, ساختار ForwardOptions *);
صحیح	 permitopen_port(ثابت نویسه *);

/* x11 forwarding */

تهی	 channel_set_x11_refuse_time(ساختار ssh *, دوگانه);
صحیح	 x11_connect_display(ساختار ssh *);
صحیح	 x11_create_display_inet(ساختار ssh *, صحیح, صحیح, صحیح, u_int *, صحیح **);
تهی	 x11_request_forwarding_with_spoofing(ساختار ssh *, صحیح,
	    ثابت نویسه *, ثابت نویسه *, ثابت نویسه *, صحیح);
صحیح      x11_channel_used_recently(ساختار ssh *ssh);

/* channel close */

صحیح	 chan_is_dead(ساختار ssh *, Channel *, صحیح);
تهی	 chan_mark_dead(ساختار ssh *, Channel *);

/* agent forwarding */
تهی	 client_channel_request_agent_forwarding(ساختار ssh *, صحیح);

/* channel events */

تهی	 chan_rcvd_oclose(ساختار ssh *, Channel *);
تهی	 chan_rcvd_eow(ساختار ssh *, Channel *);
تهی	 chan_read_failed(ساختار ssh *, Channel *);
تهی	 chan_ibuf_empty(ساختار ssh *, Channel *);
تهی	 chan_rcvd_ieof(ساختار ssh *, Channel *);
تهی	 chan_write_failed(ساختار ssh *, Channel *);
تهی	 chan_obuf_empty(ساختار ssh *, Channel *);

#endif
