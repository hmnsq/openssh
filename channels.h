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

கட்டமைப்பு ssh;
கட்டமைப்பு Channel;
வகைவரை கட்டமைப்பு Channel Channel;
கட்டமைப்பு channel_connect;

வகைவரை வெறுமை channel_open_fn(கட்டமைப்பு ssh *, முழு, முழு, வெறுமை *);
வகைவரை வெறுமை channel_callback_fn(கட்டமைப்பு ssh *, முழு, முழு, வெறுமை *);
வகைவரை முழு channel_infilter_fn(கட்டமைப்பு ssh *, கட்டமைப்பு Channel *, எழுத்து *, முழு);
வகைவரை வெறுமை channel_filter_cleanup_fn(கட்டமைப்பு ssh *, முழு, வெறுமை *);
வகைவரை u_char *channel_outfilter_fn(கட்டமைப்பு ssh *, கட்டமைப்பு Channel *,
    u_char **, size_t *);

/* Channel success/failure callbacks */
வகைவரை வெறுமை channel_confirm_cb(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு Channel *, வெறுமை *);
வகைவரை வெறுமை channel_confirm_abandon_cb(கட்டமைப்பு ssh *, கட்டமைப்பு Channel *, வெறுமை *);
கட்டமைப்பு channel_confirm {
	TAILQ_ENTRY(channel_confirm) entry;
	channel_confirm_cb *cb;
	channel_confirm_abandon_cb *abandon_cb;
	வெறுமை *ctx;
};
TAILQ_HEAD(channel_confirms, channel_confirm);

/* Callbacks for mux channels back into client-specific code */
வகைவரை முழு mux_callback_fn(கட்டமைப்பு ssh *, கட்டமைப்பு Channel *);

/*
 * NB. channel IDs on the wire and in c->remote_id are uint32, but local
 * channel IDs (e.g. c->self) only ever use the int32 subset of this range,
 * because we use local channel ID -1 for housekeeping. Remote channels have
 * a dedicated "have_remote_id" flag to indicate their validity.
 */

கட்டமைப்பு Channel {
	முழு     type;		/* channel type/state */

	முழு     self;		/* my own channel identifier */
	uint32_t remote_id;	/* channel identifier for remote peer */
	முழு	have_remote_id;	/* non-zero if remote_id is valid */

	u_int   istate;		/* input from channel (state of receive half) */
	u_int   ostate;		/* output to channel  (state of transmit half) */
	முழு     flags;		/* close sent/rcvd */
	முழு     rfd;		/* read fd */
	முழு     wfd;		/* write fd */
	முழு     efd;		/* extended fd */
	முழு     sock;		/* sock fd */
	u_int	io_want;	/* bitmask of SSH_CHAN_IO_* */
	u_int	io_ready;	/* bitmask of SSH_CHAN_IO_* */
	முழு	pfds[4];	/* pollfd entries for rfd/wfd/efd/sock */
	முழு     ctl_chan;	/* control channel (multiplexed connections) */
	uint32_t ctl_child_id;	/* child session for mux controllers */
	முழு	have_ctl_child_id;/* non-zero if ctl_child_id is valid */
	முழு     remote_has_tty;	/* remote side has a tty */
	முழு     isatty;		/* rfd is a tty */
#ifdef _AIX
	முழு     wfd_isatty;	/* wfd is a tty */
#endif
	முழு	client_tty;	/* (client) TTY has been requested */
	முழு     force_drain;	/* force close on iEOF */
	இரட்டை	notbefore;	/* Pause IO until deadline (time_t) */
	முழு     delayed;	/* post-IO handlers for newly created
				 * channels are delayed until the first call
				 * to a matching pre-IO handler.
				 * this way post-IO handlers are not
				 * accidentally called if a FD gets reused */
	முழு	restore_block;	/* fd mask to restore blocking status */
	முழு	restore_flags[3];/* flags to restore */
	கட்டமைப்பு sshbuf *உள்ளீடு;	/* data read from socket, to be sent over
				 * encrypted connection */
	கட்டமைப்பு sshbuf *output;	/* data received over encrypted connection for
				 * send on socket */
	கட்டமைப்பு sshbuf *extended;

	எழுத்து    *path;
		/* path for unix domain sockets, or host name for forwards */
	முழு     listening_port;	/* port being listened for forwards */
	எழுத்து   *listening_addr;	/* addr being listened for forwards */
	முழு     host_port;	/* remote port to connect for forwards */
	எழுத்து   *remote_name;	/* remote hostname */

	u_int	remote_window;
	u_int	remote_maxpacket;
	u_int	local_window;
	u_int	local_window_exceeded;
	u_int	local_window_max;
	u_int	local_consumed;
	u_int	local_maxpacket;
	முழு     extended_usage;
	முழு	agent_new;	/* For agent listeners, use RFC 9987 requests */
	முழு	single_connection;

	எழுத்து   *ctype;		/* const type - NB. not freed on channel_free */
	எழுத்து   *xctype;		/* extended type */
	முழு	bulk;		/* channel is non-interactive */

	/* callback */
	channel_open_fn		*open_confirm;
	வெறுமை			*open_confirm_ctx;
	channel_callback_fn	*detach_user;
	முழு			detach_close;
	கட்டமைப்பு channel_confirms	status_confirms;

	/* filter */
	channel_infilter_fn	*உள்ளீடு_filter;
	channel_outfilter_fn	*output_filter;
	வெறுமை			*filter_ctx;
	channel_filter_cleanup_fn *filter_cleanup;

	/* keep boundaries */
	முழு			datagram;

	/* non-blocking connect */
	கட்டமைப்பு channel_connect	*connect_ctx;

	/* multiplexing protocol hook, called for each packet received */
	mux_callback_fn		*mux_rcb;
	வெறுமை			*mux_ctx;
	முழு			mux_pause;
	முழு			mux_downstream_id;

	/* Inactivity timeouts */

	/* Last traffic seen for OPEN channels */
	இரட்டை			lastused;
	/* Inactivity timeout deadline in seconds (0 = no timeout) */
	இரட்டை			inactive_deadline;
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
#define CHAN_உள்ளீடு_OPEN			0
#define CHAN_உள்ளீடு_WAIT_DRAIN		1
#define CHAN_உள்ளீடு_WAIT_OCLOSE		2
#define CHAN_உள்ளீடு_CLOSED		3

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
#define CHAN_உள்ளீடு_MAX	(16*1024*1024)

/* Hard limit on number of channels */
#define CHANNELS_MAX_CHANNELS	(16*1024)

/* check whether 'efd' is still in use */
#define CHANNEL_EFD_உள்ளீடு_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_READ && \
	(c->efd != -1 || \
	sshbuf_len(c->extended) > 0))
#define CHANNEL_EFD_OUTPUT_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_WRITE && \
	c->efd != -1 && (!(c->flags & (CHAN_EOF_RCVD|CHAN_CLOSE_RCVD)) || \
	sshbuf_len(c->extended) > 0))

/* Add/remove channel management structures to/from SSH transport instance */
வெறுமை channel_init_channels(கட்டமைப்பு ssh *ssh);
வெறுமை channel_free_channels(கட்டமைப்பு ssh *ssh);

/* channel management */

Channel	*channel_by_id(கட்டமைப்பு ssh *, முழு);
Channel	*channel_by_remote_id(கட்டமைப்பு ssh *, u_int);
Channel	*channel_lookup(கட்டமைப்பு ssh *, முழு);
Channel *channel_new(கட்டமைப்பு ssh *, எழுத்து *, முழு, முழு, முழு, முழு,
	    u_int, u_int, முழு, மாறிலி எழுத்து *, முழு);
வெறுமை	 channel_set_fds(கட்டமைப்பு ssh *, முழு, முழு, முழு, முழு, முழு,
	    முழு, முழு, u_int);
வெறுமை	 channel_set_tty(கட்டமைப்பு ssh *, Channel *);
வெறுமை	 channel_free(கட்டமைப்பு ssh *, Channel *);
வெறுமை	 channel_free_all(கட்டமைப்பு ssh *);
வெறுமை	 channel_stop_listening(கட்டமைப்பு ssh *);
வெறுமை	 channel_force_close(கட்டமைப்பு ssh *, Channel *, முழு);
வெறுமை	 channel_set_xtype(கட்டமைப்பு ssh *, முழு, மாறிலி எழுத்து *);

வெறுமை	 channel_send_open(கட்டமைப்பு ssh *, முழு);
வெறுமை	 channel_request_start(கட்டமைப்பு ssh *, முழு, மாறிலி எழுத்து *, முழு);
வெறுமை	 channel_register_cleanup(கட்டமைப்பு ssh *, முழு,
	    channel_callback_fn *, முழு);
வெறுமை	 channel_register_open_confirm(கட்டமைப்பு ssh *, முழு,
	    channel_open_fn *, வெறுமை *);
வெறுமை	 channel_register_filter(கட்டமைப்பு ssh *, முழு, channel_infilter_fn *,
	    channel_outfilter_fn *, channel_filter_cleanup_fn *, வெறுமை *);
வெறுமை	 channel_register_status_confirm(கட்டமைப்பு ssh *, முழு,
	    channel_confirm_cb *, channel_confirm_abandon_cb *, வெறுமை *);
வெறுமை	 channel_cancel_cleanup(கட்டமைப்பு ssh *, முழு);
முழு	 channel_close_fd(கட்டமைப்பு ssh *, Channel *, முழு *);
வெறுமை	 channel_send_window_changes(கட்டமைப்பு ssh *);
முழு	 channel_has_bulk(கட்டமைப்பு ssh *);
வெறுமை	 channel_set_tcp_keepalives(கட்டமைப்பு ssh *, முழு);

/* channel inactivity timeouts */
வெறுமை channel_add_timeout(கட்டமைப்பு ssh *, மாறிலி எழுத்து *, இரட்டை);
வெறுமை channel_clear_timeouts(கட்டமைப்பு ssh *);

/* mux proxy support */

முழு	 channel_proxy_downstream(கட்டமைப்பு ssh *, Channel *mc);
முழு	 channel_proxy_upstream(Channel *, முழு, uint32_t, கட்டமைப்பு ssh *);

/* protocol handler */

முழு	 channel_உள்ளீடு_data(முழு, uint32_t, கட்டமைப்பு ssh *);
முழு	 channel_உள்ளீடு_extended_data(முழு, uint32_t, கட்டமைப்பு ssh *);
முழு	 channel_உள்ளீடு_ieof(முழு, uint32_t, கட்டமைப்பு ssh *);
முழு	 channel_உள்ளீடு_oclose(முழு, uint32_t, கட்டமைப்பு ssh *);
முழு	 channel_உள்ளீடு_open_confirmation(முழு, uint32_t, கட்டமைப்பு ssh *);
முழு	 channel_உள்ளீடு_open_failure(முழு, uint32_t, கட்டமைப்பு ssh *);
முழு	 channel_உள்ளீடு_window_adjust(முழு, uint32_t, கட்டமைப்பு ssh *);
முழு	 channel_உள்ளீடு_status_confirm(முழு, uint32_t, கட்டமைப்பு ssh *);

/* file descriptor handling (read/write) */
கட்டமைப்பு pollfd;
கட்டமைப்பு timespec;

வெறுமை	 channel_prepare_poll(கட்டமைப்பு ssh *, கட்டமைப்பு pollfd **,
	    u_int *, u_int *, u_int, கட்டமைப்பு timespec *);
வெறுமை	 channel_after_poll(கட்டமைப்பு ssh *, கட்டமைப்பு pollfd *, u_int);
முழு	 channel_output_poll(கட்டமைப்பு ssh *);

முழு      channel_not_very_much_buffered_data(கட்டமைப்பு ssh *);
வெறுமை     channel_close_all(கட்டமைப்பு ssh *);
முழு      channel_still_open(கட்டமைப்பு ssh *);
முழு	 channel_tty_open(கட்டமைப்பு ssh *);
மாறிலி எழுத்து *channel_format_extended_usage(மாறிலி Channel *);
எழுத்து	*channel_open_message(கட்டமைப்பு ssh *);
வெறுமை	 channel_report_open(கட்டமைப்பு ssh *, முழு);
முழு	 channel_find_open(கட்டமைப்பு ssh *);

/* tcp forwarding */
கட்டமைப்பு Forward;
கட்டமைப்பு ForwardOptions;
வெறுமை	 channel_set_af(கட்டமைப்பு ssh *, முழு af);
வெறுமை     channel_permit_all(கட்டமைப்பு ssh *, முழு);
வெறுமை	 channel_add_permission(கட்டமைப்பு ssh *, முழு, முழு, எழுத்து *, முழு);
வெறுமை	 channel_clear_permission(கட்டமைப்பு ssh *, முழு, முழு);
வெறுமை	 channel_disable_admin(கட்டமைப்பு ssh *, முழு);
வெறுமை	 channel_update_permission(கட்டமைப்பு ssh *, முழு, முழு);
Channel	*channel_connect_to_port(கட்டமைப்பு ssh *, மாறிலி எழுத்து *, u_short,
	    எழுத்து *, எழுத்து *, முழு *, மாறிலி எழுத்து **);
Channel *channel_connect_to_path(கட்டமைப்பு ssh *, மாறிலி எழுத்து *, எழுத்து *, எழுத்து *);
Channel	*channel_connect_stdio_fwd(கட்டமைப்பு ssh *, மாறிலி எழுத்து*,
	    முழு, முழு, முழு, முழு);
Channel	*channel_connect_by_listen_address(கட்டமைப்பு ssh *, மாறிலி எழுத்து *,
	    u_short, எழுத்து *, எழுத்து *);
Channel	*channel_connect_by_listen_path(கட்டமைப்பு ssh *, மாறிலி எழுத்து *,
	    எழுத்து *, எழுத்து *);
முழு	 channel_request_remote_forwarding(கட்டமைப்பு ssh *, கட்டமைப்பு Forward *);
முழு	 channel_setup_local_fwd_listener(கட்டமைப்பு ssh *, கட்டமைப்பு Forward *,
	    கட்டமைப்பு ForwardOptions *);
முழு	 channel_request_rforward_cancel(கட்டமைப்பு ssh *, கட்டமைப்பு Forward *);
முழு	 channel_setup_remote_fwd_listener(கட்டமைப்பு ssh *, கட்டமைப்பு Forward *,
	    முழு *, கட்டமைப்பு ForwardOptions *);
முழு	 channel_cancel_rport_listener(கட்டமைப்பு ssh *, கட்டமைப்பு Forward *);
முழு	 channel_cancel_lport_listener(கட்டமைப்பு ssh *, கட்டமைப்பு Forward *,
	    முழு, கட்டமைப்பு ForwardOptions *);
முழு	 permitopen_port(மாறிலி எழுத்து *);

/* x11 forwarding */

வெறுமை	 channel_set_x11_refuse_time(கட்டமைப்பு ssh *, இரட்டை);
முழு	 x11_connect_display(கட்டமைப்பு ssh *);
முழு	 x11_create_display_inet(கட்டமைப்பு ssh *, முழு, முழு, முழு, u_int *, முழு **);
வெறுமை	 x11_request_forwarding_with_spoofing(கட்டமைப்பு ssh *, முழு,
	    மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, முழு);
முழு      x11_channel_used_recently(கட்டமைப்பு ssh *ssh);

/* channel close */

முழு	 chan_is_dead(கட்டமைப்பு ssh *, Channel *, முழு);
வெறுமை	 chan_mark_dead(கட்டமைப்பு ssh *, Channel *);

/* agent forwarding */
வெறுமை	 client_channel_request_agent_forwarding(கட்டமைப்பு ssh *, முழு);

/* channel events */

வெறுமை	 chan_rcvd_oclose(கட்டமைப்பு ssh *, Channel *);
வெறுமை	 chan_rcvd_eow(கட்டமைப்பு ssh *, Channel *);
வெறுமை	 chan_read_failed(கட்டமைப்பு ssh *, Channel *);
வெறுமை	 chan_ibuf_empty(கட்டமைப்பு ssh *, Channel *);
வெறுமை	 chan_rcvd_ieof(கட்டமைப்பு ssh *, Channel *);
வெறுமை	 chan_write_failed(கட்டமைப்பு ssh *, Channel *);
வெறுமை	 chan_obuf_empty(கட்டமைப்பு ssh *, Channel *);

#endif
