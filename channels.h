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

بنية ssh;
بنية Channel;
تعريفنوع بنية Channel Channel;
بنية channel_connect;

تعريفنوع فراغ channel_open_fn(بنية ssh *, صحيح, صحيح, فراغ *);
تعريفنوع فراغ channel_callback_fn(بنية ssh *, صحيح, صحيح, فراغ *);
تعريفنوع صحيح channel_infilter_fn(بنية ssh *, بنية Channel *, حرف *, صحيح);
تعريفنوع فراغ channel_filter_cleanup_fn(بنية ssh *, صحيح, فراغ *);
تعريفنوع u_char *channel_outfilter_fn(بنية ssh *, بنية Channel *,
    u_char **, size_t *);

/* Channel success/failure callbacks */
تعريفنوع فراغ channel_confirm_cb(بنية ssh *, صحيح, بنية Channel *, فراغ *);
تعريفنوع فراغ channel_confirm_abandon_cb(بنية ssh *, بنية Channel *, فراغ *);
بنية channel_confirm {
	TAILQ_ENTRY(channel_confirm) entry;
	channel_confirm_cb *cb;
	channel_confirm_abandon_cb *abandon_cb;
	فراغ *ctx;
};
TAILQ_HEAD(channel_confirms, channel_confirm);

/* Callbacks for mux channels back into client-specific code */
تعريفنوع صحيح mux_callback_fn(بنية ssh *, بنية Channel *);

/*
 * NB. channel IDs on the wire and in c->remote_id are uint32, but local
 * channel IDs (e.g. c->self) only ever use the int32 subset of this range,
 * because we use local channel ID -1 for housekeeping. Remote channels have
 * a dedicated "have_remote_id" flag to indicate their validity.
 */

بنية Channel {
	صحيح     type;		/* channel type/state */

	صحيح     self;		/* my own channel identifier */
	uint32_t remote_id;	/* channel identifier for remote peer */
	صحيح	have_remote_id;	/* non-zero if remote_id is valid */

	u_int   istate;		/* input from channel (state of receive half) */
	u_int   ostate;		/* output to channel  (state of transmit half) */
	صحيح     flags;		/* close sent/rcvd */
	صحيح     rfd;		/* read fd */
	صحيح     wfd;		/* write fd */
	صحيح     efd;		/* extended fd */
	صحيح     sock;		/* sock fd */
	u_int	io_want;	/* bitmask of SSH_CHAN_IO_* */
	u_int	io_ready;	/* bitmask of SSH_CHAN_IO_* */
	صحيح	pfds[4];	/* pollfd entries for rfd/wfd/efd/sock */
	صحيح     ctl_chan;	/* control channel (multiplexed connections) */
	uint32_t ctl_child_id;	/* child session for mux controllers */
	صحيح	have_ctl_child_id;/* non-zero if ctl_child_id is valid */
	صحيح     remote_has_tty;	/* remote side has a tty */
	صحيح     isatty;		/* rfd is a tty */
#ifdef _AIX
	صحيح     wfd_isatty;	/* wfd is a tty */
#endif
	صحيح	client_tty;	/* (client) TTY has been requested */
	صحيح     force_drain;	/* force close on iEOF */
	مزدوج	notbefore;	/* Pause IO until deadline (time_t) */
	صحيح     delayed;	/* post-IO handlers for newly created
				 * channels are delayed until the first call
				 * to a matching pre-IO handler.
				 * this way post-IO handlers are not
				 * accidentally called if a FD gets reused */
	صحيح	restore_block;	/* fd mask to restore blocking status */
	صحيح	restore_flags[3];/* flags to restore */
	بنية sshbuf *input;	/* data read from socket, to be sent over
				 * encrypted connection */
	بنية sshbuf *output;	/* data received over encrypted connection for
				 * send on socket */
	بنية sshbuf *extended;

	حرف    *path;
		/* path for unix domain sockets, or host name for forwards */
	صحيح     listening_port;	/* port being listened for forwards */
	حرف   *listening_addr;	/* addr being listened for forwards */
	صحيح     host_port;	/* remote port to connect for forwards */
	حرف   *remote_name;	/* remote hostname */

	u_int	remote_window;
	u_int	remote_maxpacket;
	u_int	local_window;
	u_int	local_window_exceeded;
	u_int	local_window_max;
	u_int	local_consumed;
	u_int	local_maxpacket;
	صحيح     extended_usage;
	صحيح	agent_new;	/* For agent listeners, use RFC 9987 requests */
	صحيح	single_connection;

	حرف   *ctype;		/* const type - NB. not freed on channel_free */
	حرف   *xctype;		/* extended type */
	صحيح	bulk;		/* channel is non-interactive */

	/* callback */
	channel_open_fn		*open_confirm;
	فراغ			*open_confirm_ctx;
	channel_callback_fn	*detach_user;
	صحيح			detach_close;
	بنية channel_confirms	status_confirms;

	/* filter */
	channel_infilter_fn	*input_filter;
	channel_outfilter_fn	*output_filter;
	فراغ			*filter_ctx;
	channel_filter_cleanup_fn *filter_cleanup;

	/* keep boundaries */
	صحيح			datagram;

	/* non-blocking connect */
	بنية channel_connect	*connect_ctx;

	/* multiplexing protocol hook, called for each packet received */
	mux_callback_fn		*mux_rcb;
	فراغ			*mux_ctx;
	صحيح			mux_pause;
	صحيح			mux_downstream_id;

	/* Inactivity timeouts */

	/* Last traffic seen for OPEN channels */
	مزدوج			lastused;
	/* Inactivity timeout deadline in seconds (0 = no timeout) */
	مزدوج			inactive_deadline;
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
#define CHAN_INPUT_OPEN			0
#define CHAN_INPUT_WAIT_DRAIN		1
#define CHAN_INPUT_WAIT_OCLOSE		2
#define CHAN_INPUT_CLOSED		3

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
#define CHAN_INPUT_MAX	(16*1024*1024)

/* Hard limit on number of channels */
#define CHANNELS_MAX_CHANNELS	(16*1024)

/* check whether 'efd' is still in use */
#define CHANNEL_EFD_INPUT_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_READ && \
	(c->efd != -1 || \
	sshbuf_len(c->extended) > 0))
#define CHANNEL_EFD_OUTPUT_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_WRITE && \
	c->efd != -1 && (!(c->flags & (CHAN_EOF_RCVD|CHAN_CLOSE_RCVD)) || \
	sshbuf_len(c->extended) > 0))

/* Add/remove channel management structures to/from SSH transport instance */
فراغ channel_init_channels(بنية ssh *ssh);
فراغ channel_free_channels(بنية ssh *ssh);

/* channel management */

Channel	*channel_by_id(بنية ssh *, صحيح);
Channel	*channel_by_remote_id(بنية ssh *, u_int);
Channel	*channel_lookup(بنية ssh *, صحيح);
Channel *channel_new(بنية ssh *, حرف *, صحيح, صحيح, صحيح, صحيح,
	    u_int, u_int, صحيح, ثابت حرف *, صحيح);
فراغ	 channel_set_fds(بنية ssh *, صحيح, صحيح, صحيح, صحيح, صحيح,
	    صحيح, صحيح, u_int);
فراغ	 channel_set_tty(بنية ssh *, Channel *);
فراغ	 channel_free(بنية ssh *, Channel *);
فراغ	 channel_free_all(بنية ssh *);
فراغ	 channel_stop_listening(بنية ssh *);
فراغ	 channel_force_close(بنية ssh *, Channel *, صحيح);
فراغ	 channel_set_xtype(بنية ssh *, صحيح, ثابت حرف *);

فراغ	 channel_send_open(بنية ssh *, صحيح);
فراغ	 channel_request_start(بنية ssh *, صحيح, ثابت حرف *, صحيح);
فراغ	 channel_register_cleanup(بنية ssh *, صحيح,
	    channel_callback_fn *, صحيح);
فراغ	 channel_register_open_confirm(بنية ssh *, صحيح,
	    channel_open_fn *, فراغ *);
فراغ	 channel_register_filter(بنية ssh *, صحيح, channel_infilter_fn *,
	    channel_outfilter_fn *, channel_filter_cleanup_fn *, فراغ *);
فراغ	 channel_register_status_confirm(بنية ssh *, صحيح,
	    channel_confirm_cb *, channel_confirm_abandon_cb *, فراغ *);
فراغ	 channel_cancel_cleanup(بنية ssh *, صحيح);
صحيح	 channel_close_fd(بنية ssh *, Channel *, صحيح *);
فراغ	 channel_send_window_changes(بنية ssh *);
صحيح	 channel_has_bulk(بنية ssh *);
فراغ	 channel_set_tcp_keepalives(بنية ssh *, صحيح);

/* channel inactivity timeouts */
فراغ channel_add_timeout(بنية ssh *, ثابت حرف *, مزدوج);
فراغ channel_clear_timeouts(بنية ssh *);

/* mux proxy support */

صحيح	 channel_proxy_downstream(بنية ssh *, Channel *mc);
صحيح	 channel_proxy_upstream(Channel *, صحيح, uint32_t, بنية ssh *);

/* protocol handler */

صحيح	 channel_input_data(صحيح, uint32_t, بنية ssh *);
صحيح	 channel_input_extended_data(صحيح, uint32_t, بنية ssh *);
صحيح	 channel_input_ieof(صحيح, uint32_t, بنية ssh *);
صحيح	 channel_input_oclose(صحيح, uint32_t, بنية ssh *);
صحيح	 channel_input_open_confirmation(صحيح, uint32_t, بنية ssh *);
صحيح	 channel_input_open_failure(صحيح, uint32_t, بنية ssh *);
صحيح	 channel_input_window_adjust(صحيح, uint32_t, بنية ssh *);
صحيح	 channel_input_status_confirm(صحيح, uint32_t, بنية ssh *);

/* file descriptor handling (read/write) */
بنية pollfd;
بنية timespec;

فراغ	 channel_prepare_poll(بنية ssh *, بنية pollfd **,
	    u_int *, u_int *, u_int, بنية timespec *);
فراغ	 channel_after_poll(بنية ssh *, بنية pollfd *, u_int);
صحيح	 channel_output_poll(بنية ssh *);

صحيح      channel_not_very_much_buffered_data(بنية ssh *);
فراغ     channel_close_all(بنية ssh *);
صحيح      channel_still_open(بنية ssh *);
صحيح	 channel_tty_open(بنية ssh *);
ثابت حرف *channel_format_extended_usage(ثابت Channel *);
حرف	*channel_open_message(بنية ssh *);
فراغ	 channel_report_open(بنية ssh *, صحيح);
صحيح	 channel_find_open(بنية ssh *);

/* tcp forwarding */
بنية Forward;
بنية ForwardOptions;
فراغ	 channel_set_af(بنية ssh *, صحيح af);
فراغ     channel_permit_all(بنية ssh *, صحيح);
فراغ	 channel_add_permission(بنية ssh *, صحيح, صحيح, حرف *, صحيح);
فراغ	 channel_clear_permission(بنية ssh *, صحيح, صحيح);
فراغ	 channel_disable_admin(بنية ssh *, صحيح);
فراغ	 channel_update_permission(بنية ssh *, صحيح, صحيح);
Channel	*channel_connect_to_port(بنية ssh *, ثابت حرف *, u_short,
	    حرف *, حرف *, صحيح *, ثابت حرف **);
Channel *channel_connect_to_path(بنية ssh *, ثابت حرف *, حرف *, حرف *);
Channel	*channel_connect_stdio_fwd(بنية ssh *, ثابت حرف*,
	    صحيح, صحيح, صحيح, صحيح);
Channel	*channel_connect_by_listen_address(بنية ssh *, ثابت حرف *,
	    u_short, حرف *, حرف *);
Channel	*channel_connect_by_listen_path(بنية ssh *, ثابت حرف *,
	    حرف *, حرف *);
صحيح	 channel_request_remote_forwarding(بنية ssh *, بنية Forward *);
صحيح	 channel_setup_local_fwd_listener(بنية ssh *, بنية Forward *,
	    بنية ForwardOptions *);
صحيح	 channel_request_rforward_cancel(بنية ssh *, بنية Forward *);
صحيح	 channel_setup_remote_fwd_listener(بنية ssh *, بنية Forward *,
	    صحيح *, بنية ForwardOptions *);
صحيح	 channel_cancel_rport_listener(بنية ssh *, بنية Forward *);
صحيح	 channel_cancel_lport_listener(بنية ssh *, بنية Forward *,
	    صحيح, بنية ForwardOptions *);
صحيح	 permitopen_port(ثابت حرف *);

/* x11 forwarding */

فراغ	 channel_set_x11_refuse_time(بنية ssh *, مزدوج);
صحيح	 x11_connect_display(بنية ssh *);
صحيح	 x11_create_display_inet(بنية ssh *, صحيح, صحيح, صحيح, u_int *, صحيح **);
فراغ	 x11_request_forwarding_with_spoofing(بنية ssh *, صحيح,
	    ثابت حرف *, ثابت حرف *, ثابت حرف *, صحيح);
صحيح      x11_channel_used_recently(بنية ssh *ssh);

/* channel close */

صحيح	 chan_is_dead(بنية ssh *, Channel *, صحيح);
فراغ	 chan_mark_dead(بنية ssh *, Channel *);

/* agent forwarding */
فراغ	 client_channel_request_agent_forwarding(بنية ssh *, صحيح);

/* channel events */

فراغ	 chan_rcvd_oclose(بنية ssh *, Channel *);
فراغ	 chan_rcvd_eow(بنية ssh *, Channel *);
فراغ	 chan_read_failed(بنية ssh *, Channel *);
فراغ	 chan_ibuf_empty(بنية ssh *, Channel *);
فراغ	 chan_rcvd_ieof(بنية ssh *, Channel *);
فراغ	 chan_write_failed(بنية ssh *, Channel *);
فراغ	 chan_obuf_empty(بنية ssh *, Channel *);

#endif
