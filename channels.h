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

સંરચના ssh;
સંરચના Channel;
પ્રકારવ્યાખ્યા સંરચના Channel Channel;
સંરચના channel_connect;

પ્રકારવ્યાખ્યા શૂન્ય channel_open_fn(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક, શૂન્ય *);
પ્રકારવ્યાખ્યા શૂન્ય channel_callback_fn(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક, શૂન્ય *);
પ્રકારવ્યાખ્યા પૂર્ણાંક channel_infilter_fn(સંરચના ssh *, સંરચના Channel *, અક્ષર *, પૂર્ણાંક);
પ્રકારવ્યાખ્યા શૂન્ય channel_filter_cleanup_fn(સંરચના ssh *, પૂર્ણાંક, શૂન્ય *);
પ્રકારવ્યાખ્યા u_char *channel_outfilter_fn(સંરચના ssh *, સંરચના Channel *,
    u_char **, size_t *);

/* Channel success/failure callbacks */
પ્રકારવ્યાખ્યા શૂન્ય channel_confirm_cb(સંરચના ssh *, પૂર્ણાંક, સંરચના Channel *, શૂન્ય *);
પ્રકારવ્યાખ્યા શૂન્ય channel_confirm_abandon_cb(સંરચના ssh *, સંરચના Channel *, શૂન્ય *);
સંરચના channel_confirm {
	TAILQ_ENTRY(channel_confirm) entry;
	channel_confirm_cb *cb;
	channel_confirm_abandon_cb *abandon_cb;
	શૂન્ય *ctx;
};
TAILQ_HEAD(channel_confirms, channel_confirm);

/* Callbacks for mux channels back into client-specific code */
પ્રકારવ્યાખ્યા પૂર્ણાંક mux_callback_fn(સંરચના ssh *, સંરચના Channel *);

/*
 * NB. channel IDs on the wire and in c->remote_id are uint32, but local
 * channel IDs (e.g. c->self) only ever use the int32 subset of this range,
 * because we use local channel ID -1 for housekeeping. Remote channels have
 * a dedicated "have_remote_id" flag to indicate their validity.
 */

સંરચના Channel {
	પૂર્ણાંક     type;		/* channel type/state */

	પૂર્ણાંક     self;		/* my own channel identifier */
	uint32_t remote_id;	/* channel identifier for remote peer */
	પૂર્ણાંક	have_remote_id;	/* non-zero if remote_id is valid */

	u_int   istate;		/* input from channel (state of receive half) */
	u_int   ostate;		/* output to channel  (state of transmit half) */
	પૂર્ણાંક     flags;		/* close sent/rcvd */
	પૂર્ણાંક     rfd;		/* read fd */
	પૂર્ણાંક     wfd;		/* write fd */
	પૂર્ણાંક     efd;		/* extended fd */
	પૂર્ણાંક     sock;		/* sock fd */
	u_int	io_want;	/* bitmask of SSH_CHAN_IO_* */
	u_int	io_ready;	/* bitmask of SSH_CHAN_IO_* */
	પૂર્ણાંક	pfds[4];	/* pollfd entries for rfd/wfd/efd/sock */
	પૂર્ણાંક     ctl_chan;	/* control channel (multiplexed connections) */
	uint32_t ctl_child_id;	/* child session for mux controllers */
	પૂર્ણાંક	have_ctl_child_id;/* non-zero if ctl_child_id is valid */
	પૂર્ણાંક     remote_has_tty;	/* remote side has a tty */
	પૂર્ણાંક     isatty;		/* rfd is a tty */
#ifdef _AIX
	પૂર્ણાંક     wfd_isatty;	/* wfd is a tty */
#endif
	પૂર્ણાંક	client_tty;	/* (client) TTY has been requested */
	પૂર્ણાંક     force_drain;	/* force close on iEOF */
	દ્વિગુણ	notbefore;	/* Pause IO until deadline (time_t) */
	પૂર્ણાંક     delayed;	/* post-IO handlers for newly created
				 * channels are delayed until the first call
				 * to a matching pre-IO handler.
				 * this way post-IO handlers are not
				 * accidentally called if a FD gets reused */
	પૂર્ણાંક	restore_block;	/* fd mask to restore blocking status */
	પૂર્ણાંક	restore_flags[3];/* flags to restore */
	સંરચના sshbuf *આગત;	/* data read from socket, to be sent over
				 * encrypted connection */
	સંરચના sshbuf *output;	/* data received over encrypted connection for
				 * send on socket */
	સંરચના sshbuf *extended;

	અક્ષર    *path;
		/* path for unix domain sockets, or host name for forwards */
	પૂર્ણાંક     listening_port;	/* port being listened for forwards */
	અક્ષર   *listening_addr;	/* addr being listened for forwards */
	પૂર્ણાંક     host_port;	/* remote port to connect for forwards */
	અક્ષર   *remote_name;	/* remote hostname */

	u_int	remote_window;
	u_int	remote_maxpacket;
	u_int	local_window;
	u_int	local_window_exceeded;
	u_int	local_window_max;
	u_int	local_consumed;
	u_int	local_maxpacket;
	પૂર્ણાંક     extended_usage;
	પૂર્ણાંક	agent_new;	/* For agent listeners, use RFC 9987 requests */
	પૂર્ણાંક	single_connection;

	અક્ષર   *ctype;		/* const type - NB. not freed on channel_free */
	અક્ષર   *xctype;		/* extended type */
	પૂર્ણાંક	bulk;		/* channel is non-interactive */

	/* callback */
	channel_open_fn		*open_confirm;
	શૂન્ય			*open_confirm_ctx;
	channel_callback_fn	*detach_user;
	પૂર્ણાંક			detach_close;
	સંરચના channel_confirms	status_confirms;

	/* filter */
	channel_infilter_fn	*આગત_filter;
	channel_outfilter_fn	*output_filter;
	શૂન્ય			*filter_ctx;
	channel_filter_cleanup_fn *filter_cleanup;

	/* keep boundaries */
	પૂર્ણાંક			datagram;

	/* non-blocking connect */
	સંરચના channel_connect	*connect_ctx;

	/* multiplexing protocol hook, called for each packet received */
	mux_callback_fn		*mux_rcb;
	શૂન્ય			*mux_ctx;
	પૂર્ણાંક			mux_pause;
	પૂર્ણાંક			mux_downstream_id;

	/* Inactivity timeouts */

	/* Last traffic seen for OPEN channels */
	દ્વિગુણ			lastused;
	/* Inactivity timeout deadline in seconds (0 = no timeout) */
	દ્વિગુણ			inactive_deadline;
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
#define CHAN_આગત_OPEN			0
#define CHAN_આગત_WAIT_DRAIN		1
#define CHAN_આગત_WAIT_OCLOSE		2
#define CHAN_આગત_CLOSED		3

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
#define CHAN_આગત_MAX	(16*1024*1024)

/* Hard limit on number of channels */
#define CHANNELS_MAX_CHANNELS	(16*1024)

/* check whether 'efd' is still in use */
#define CHANNEL_EFD_આગત_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_READ && \
	(c->efd != -1 || \
	sshbuf_len(c->extended) > 0))
#define CHANNEL_EFD_OUTPUT_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_WRITE && \
	c->efd != -1 && (!(c->flags & (CHAN_EOF_RCVD|CHAN_CLOSE_RCVD)) || \
	sshbuf_len(c->extended) > 0))

/* Add/remove channel management structures to/from SSH transport instance */
શૂન્ય channel_init_channels(સંરચના ssh *ssh);
શૂન્ય channel_free_channels(સંરચના ssh *ssh);

/* channel management */

Channel	*channel_by_id(સંરચના ssh *, પૂર્ણાંક);
Channel	*channel_by_remote_id(સંરચના ssh *, u_int);
Channel	*channel_lookup(સંરચના ssh *, પૂર્ણાંક);
Channel *channel_new(સંરચના ssh *, અક્ષર *, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક,
	    u_int, u_int, પૂર્ણાંક, અચલ અક્ષર *, પૂર્ણાંક);
શૂન્ય	 channel_set_fds(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક,
	    પૂર્ણાંક, પૂર્ણાંક, u_int);
શૂન્ય	 channel_set_tty(સંરચના ssh *, Channel *);
શૂન્ય	 channel_free(સંરચના ssh *, Channel *);
શૂન્ય	 channel_free_all(સંરચના ssh *);
શૂન્ય	 channel_stop_listening(સંરચના ssh *);
શૂન્ય	 channel_force_close(સંરચના ssh *, Channel *, પૂર્ણાંક);
શૂન્ય	 channel_set_xtype(સંરચના ssh *, પૂર્ણાંક, અચલ અક્ષર *);

શૂન્ય	 channel_send_open(સંરચના ssh *, પૂર્ણાંક);
શૂન્ય	 channel_request_start(સંરચના ssh *, પૂર્ણાંક, અચલ અક્ષર *, પૂર્ણાંક);
શૂન્ય	 channel_register_cleanup(સંરચના ssh *, પૂર્ણાંક,
	    channel_callback_fn *, પૂર્ણાંક);
શૂન્ય	 channel_register_open_confirm(સંરચના ssh *, પૂર્ણાંક,
	    channel_open_fn *, શૂન્ય *);
શૂન્ય	 channel_register_filter(સંરચના ssh *, પૂર્ણાંક, channel_infilter_fn *,
	    channel_outfilter_fn *, channel_filter_cleanup_fn *, શૂન્ય *);
શૂન્ય	 channel_register_status_confirm(સંરચના ssh *, પૂર્ણાંક,
	    channel_confirm_cb *, channel_confirm_abandon_cb *, શૂન્ય *);
શૂન્ય	 channel_cancel_cleanup(સંરચના ssh *, પૂર્ણાંક);
પૂર્ણાંક	 channel_close_fd(સંરચના ssh *, Channel *, પૂર્ણાંક *);
શૂન્ય	 channel_send_window_changes(સંરચના ssh *);
પૂર્ણાંક	 channel_has_bulk(સંરચના ssh *);
શૂન્ય	 channel_set_tcp_keepalives(સંરચના ssh *, પૂર્ણાંક);

/* channel inactivity timeouts */
શૂન્ય channel_add_timeout(સંરચના ssh *, અચલ અક્ષર *, દ્વિગુણ);
શૂન્ય channel_clear_timeouts(સંરચના ssh *);

/* mux proxy support */

પૂર્ણાંક	 channel_proxy_downstream(સંરચના ssh *, Channel *mc);
પૂર્ણાંક	 channel_proxy_upstream(Channel *, પૂર્ણાંક, uint32_t, સંરચના ssh *);

/* protocol handler */

પૂર્ણાંક	 channel_આગત_data(પૂર્ણાંક, uint32_t, સંરચના ssh *);
પૂર્ણાંક	 channel_આગત_extended_data(પૂર્ણાંક, uint32_t, સંરચના ssh *);
પૂર્ણાંક	 channel_આગત_ieof(પૂર્ણાંક, uint32_t, સંરચના ssh *);
પૂર્ણાંક	 channel_આગત_oclose(પૂર્ણાંક, uint32_t, સંરચના ssh *);
પૂર્ણાંક	 channel_આગત_open_confirmation(પૂર્ણાંક, uint32_t, સંરચના ssh *);
પૂર્ણાંક	 channel_આગત_open_failure(પૂર્ણાંક, uint32_t, સંરચના ssh *);
પૂર્ણાંક	 channel_આગત_window_adjust(પૂર્ણાંક, uint32_t, સંરચના ssh *);
પૂર્ણાંક	 channel_આગત_status_confirm(પૂર્ણાંક, uint32_t, સંરચના ssh *);

/* file descriptor handling (read/write) */
સંરચના pollfd;
સંરચના timespec;

શૂન્ય	 channel_prepare_poll(સંરચના ssh *, સંરચના pollfd **,
	    u_int *, u_int *, u_int, સંરચના timespec *);
શૂન્ય	 channel_after_poll(સંરચના ssh *, સંરચના pollfd *, u_int);
પૂર્ણાંક	 channel_output_poll(સંરચના ssh *);

પૂર્ણાંક      channel_not_very_much_buffered_data(સંરચના ssh *);
શૂન્ય     channel_close_all(સંરચના ssh *);
પૂર્ણાંક      channel_still_open(સંરચના ssh *);
પૂર્ણાંક	 channel_tty_open(સંરચના ssh *);
અચલ અક્ષર *channel_format_extended_usage(અચલ Channel *);
અક્ષર	*channel_open_message(સંરચના ssh *);
શૂન્ય	 channel_report_open(સંરચના ssh *, પૂર્ણાંક);
પૂર્ણાંક	 channel_find_open(સંરચના ssh *);

/* tcp forwarding */
સંરચના Forward;
સંરચના ForwardOptions;
શૂન્ય	 channel_set_af(સંરચના ssh *, પૂર્ણાંક af);
શૂન્ય     channel_permit_all(સંરચના ssh *, પૂર્ણાંક);
શૂન્ય	 channel_add_permission(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક, અક્ષર *, પૂર્ણાંક);
શૂન્ય	 channel_clear_permission(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક);
શૂન્ય	 channel_disable_admin(સંરચના ssh *, પૂર્ણાંક);
શૂન્ય	 channel_update_permission(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક);
Channel	*channel_connect_to_port(સંરચના ssh *, અચલ અક્ષર *, u_short,
	    અક્ષર *, અક્ષર *, પૂર્ણાંક *, અચલ અક્ષર **);
Channel *channel_connect_to_path(સંરચના ssh *, અચલ અક્ષર *, અક્ષર *, અક્ષર *);
Channel	*channel_connect_stdio_fwd(સંરચના ssh *, અચલ અક્ષર*,
	    પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક);
Channel	*channel_connect_by_listen_address(સંરચના ssh *, અચલ અક્ષર *,
	    u_short, અક્ષર *, અક્ષર *);
Channel	*channel_connect_by_listen_path(સંરચના ssh *, અચલ અક્ષર *,
	    અક્ષર *, અક્ષર *);
પૂર્ણાંક	 channel_request_remote_forwarding(સંરચના ssh *, સંરચના Forward *);
પૂર્ણાંક	 channel_setup_local_fwd_listener(સંરચના ssh *, સંરચના Forward *,
	    સંરચના ForwardOptions *);
પૂર્ણાંક	 channel_request_rforward_cancel(સંરચના ssh *, સંરચના Forward *);
પૂર્ણાંક	 channel_setup_remote_fwd_listener(સંરચના ssh *, સંરચના Forward *,
	    પૂર્ણાંક *, સંરચના ForwardOptions *);
પૂર્ણાંક	 channel_cancel_rport_listener(સંરચના ssh *, સંરચના Forward *);
પૂર્ણાંક	 channel_cancel_lport_listener(સંરચના ssh *, સંરચના Forward *,
	    પૂર્ણાંક, સંરચના ForwardOptions *);
પૂર્ણાંક	 permitopen_port(અચલ અક્ષર *);

/* x11 forwarding */

શૂન્ય	 channel_set_x11_refuse_time(સંરચના ssh *, દ્વિગુણ);
પૂર્ણાંક	 x11_connect_display(સંરચના ssh *);
પૂર્ણાંક	 x11_create_display_inet(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, u_int *, પૂર્ણાંક **);
શૂન્ય	 x11_request_forwarding_with_spoofing(સંરચના ssh *, પૂર્ણાંક,
	    અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *, પૂર્ણાંક);
પૂર્ણાંક      x11_channel_used_recently(સંરચના ssh *ssh);

/* channel close */

પૂર્ણાંક	 chan_is_dead(સંરચના ssh *, Channel *, પૂર્ણાંક);
શૂન્ય	 chan_mark_dead(સંરચના ssh *, Channel *);

/* agent forwarding */
શૂન્ય	 client_channel_request_agent_forwarding(સંરચના ssh *, પૂર્ણાંક);

/* channel events */

શૂન્ય	 chan_rcvd_oclose(સંરચના ssh *, Channel *);
શૂન્ય	 chan_rcvd_eow(સંરચના ssh *, Channel *);
શૂન્ય	 chan_read_failed(સંરચના ssh *, Channel *);
શૂન્ય	 chan_ibuf_empty(સંરચના ssh *, Channel *);
શૂન્ય	 chan_rcvd_ieof(સંરચના ssh *, Channel *);
શૂન્ય	 chan_write_failed(સંરચના ssh *, Channel *);
શૂન્ય	 chan_obuf_empty(સંરચના ssh *, Channel *);

#endif
