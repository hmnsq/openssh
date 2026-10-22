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

কাঠামো ssh;
কাঠামো Channel;
প্রকারলেখ কাঠামো Channel Channel;
কাঠামো channel_connect;

প্রকারলেখ শূন্য channel_open_fn(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা, শূন্য *);
প্রকারলেখ শূন্য channel_callback_fn(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা, শূন্য *);
প্রকারলেখ পূর্ণসংখ্যা channel_infilter_fn(কাঠামো ssh *, কাঠামো Channel *, অক্ষর *, পূর্ণসংখ্যা);
প্রকারলেখ শূন্য channel_filter_cleanup_fn(কাঠামো ssh *, পূর্ণসংখ্যা, শূন্য *);
প্রকারলেখ u_char *channel_outfilter_fn(কাঠামো ssh *, কাঠামো Channel *,
    u_char **, আকার_t *);

/* Channel success/failure callbacks */
প্রকারলেখ শূন্য channel_confirm_cb(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো Channel *, শূন্য *);
প্রকারলেখ শূন্য channel_confirm_abandon_cb(কাঠামো ssh *, কাঠামো Channel *, শূন্য *);
কাঠামো channel_confirm {
	TAILQ_ENTRY(channel_confirm) entry;
	channel_confirm_cb *cb;
	channel_confirm_abandon_cb *abandon_cb;
	শূন্য *ctx;
};
TAILQ_HEAD(channel_confirms, channel_confirm);

/* Callbacks for mux channels back into client-specific code */
প্রকারলেখ পূর্ণসংখ্যা mux_callback_fn(কাঠামো ssh *, কাঠামো Channel *);

/*
 * NB. channel IDs on the wire and in c->remote_id are uint32, but local
 * channel IDs (e.g. c->self) only ever use the int32 subset of this range,
 * because we use local channel ID -1 for housekeeping. Remote channels have
 * a dedicated "have_remote_id" flag to indicate their validity.
 */

কাঠামো Channel {
	পূর্ণসংখ্যা     type;		/* channel type/state */

	পূর্ণসংখ্যা     self;		/* my own channel identifier */
	uint32_t remote_id;	/* channel identifier for remote peer */
	পূর্ণসংখ্যা	have_remote_id;	/* non-zero if remote_id is valid */

	u_int   istate;		/* input from channel (state of receive half) */
	u_int   ostate;		/* output to channel  (state of transmit half) */
	পূর্ণসংখ্যা     flags;		/* close sent/rcvd */
	পূর্ণসংখ্যা     rfd;		/* read fd */
	পূর্ণসংখ্যা     wfd;		/* write fd */
	পূর্ণসংখ্যা     efd;		/* extended fd */
	পূর্ণসংখ্যা     sock;		/* sock fd */
	u_int	io_want;	/* bitmask of SSH_CHAN_IO_* */
	u_int	io_ready;	/* bitmask of SSH_CHAN_IO_* */
	পূর্ণসংখ্যা	pfds[4];	/* pollfd entries for rfd/wfd/efd/sock */
	পূর্ণসংখ্যা     ctl_chan;	/* control channel (multiplexed connections) */
	uint32_t ctl_child_id;	/* child session for mux controllers */
	পূর্ণসংখ্যা	have_ctl_child_id;/* non-zero if ctl_child_id is valid */
	পূর্ণসংখ্যা     remote_has_tty;	/* remote side has a tty */
	পূর্ণসংখ্যা     isatty;		/* rfd is a tty */
#ifdef _AIX
	পূর্ণসংখ্যা     wfd_isatty;	/* wfd is a tty */
#endif
	পূর্ণসংখ্যা	client_tty;	/* (client) TTY has been requested */
	পূর্ণসংখ্যা     force_drain;	/* force close on iEOF */
	দ্বিগুণ	notbefore;	/* Pause IO until deadline (time_t) */
	পূর্ণসংখ্যা     delayed;	/* post-IO handlers for newly created
				 * channels are delayed until the first call
				 * to a matching pre-IO handler.
				 * this way post-IO handlers are not
				 * accidentally called if a FD gets reused */
	পূর্ণসংখ্যা	restore_block;	/* fd mask to restore blocking status */
	পূর্ণসংখ্যা	restore_flags[3];/* flags to restore */
	কাঠামো sshbuf *প্রবেশ;	/* data read from socket, to be sent over
				 * encrypted connection */
	কাঠামো sshbuf *output;	/* data received over encrypted connection for
				 * send on socket */
	কাঠামো sshbuf *extended;

	অক্ষর    *path;
		/* path for unix domain sockets, or host name for forwards */
	পূর্ণসংখ্যা     listening_port;	/* port being listened for forwards */
	অক্ষর   *listening_addr;	/* addr being listened for forwards */
	পূর্ণসংখ্যা     host_port;	/* remote port to connect for forwards */
	অক্ষর   *remote_name;	/* remote hostname */

	u_int	remote_window;
	u_int	remote_maxpacket;
	u_int	local_window;
	u_int	local_window_exceeded;
	u_int	local_window_max;
	u_int	local_consumed;
	u_int	local_maxpacket;
	পূর্ণসংখ্যা     extended_usage;
	পূর্ণসংখ্যা	agent_new;	/* For agent listeners, use RFC 9987 requests */
	পূর্ণসংখ্যা	single_connection;

	অক্ষর   *ctype;		/* const type - NB. not freed on channel_free */
	অক্ষর   *xctype;		/* extended type */
	পূর্ণসংখ্যা	bulk;		/* channel is non-interactive */

	/* callback */
	channel_open_fn		*open_confirm;
	শূন্য			*open_confirm_ctx;
	channel_callback_fn	*detach_user;
	পূর্ণসংখ্যা			detach_close;
	কাঠামো channel_confirms	status_confirms;

	/* filter */
	channel_infilter_fn	*প্রবেশ_filter;
	channel_outfilter_fn	*output_filter;
	শূন্য			*filter_ctx;
	channel_filter_cleanup_fn *filter_cleanup;

	/* keep boundaries */
	পূর্ণসংখ্যা			datagram;

	/* non-blocking connect */
	কাঠামো channel_connect	*connect_ctx;

	/* multiplexing protocol hook, called for each packet received */
	mux_callback_fn		*mux_rcb;
	শূন্য			*mux_ctx;
	পূর্ণসংখ্যা			mux_pause;
	পূর্ণসংখ্যা			mux_downstream_id;

	/* Inactivity timeouts */

	/* Last traffic seen for OPEN channels */
	দ্বিগুণ			lastused;
	/* Inactivity timeout deadline in seconds (0 = no timeout) */
	দ্বিগুণ			inactive_deadline;
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
#define CHAN_প্রবেশ_OPEN			0
#define CHAN_প্রবেশ_WAIT_DRAIN		1
#define CHAN_প্রবেশ_WAIT_OCLOSE		2
#define CHAN_প্রবেশ_CLOSED		3

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
#define CHAN_প্রবেশ_MAX	(16*1024*1024)

/* Hard limit on number of channels */
#define CHANNELS_MAX_CHANNELS	(16*1024)

/* check whether 'efd' is still in use */
#define CHANNEL_EFD_প্রবেশ_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_READ && \
	(c->efd != -1 || \
	sshbuf_len(c->extended) > 0))
#define CHANNEL_EFD_OUTPUT_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_WRITE && \
	c->efd != -1 && (!(c->flags & (CHAN_EOF_RCVD|CHAN_CLOSE_RCVD)) || \
	sshbuf_len(c->extended) > 0))

/* Add/remove channel management structures to/from SSH transport instance */
শূন্য channel_init_channels(কাঠামো ssh *ssh);
শূন্য channel_free_channels(কাঠামো ssh *ssh);

/* channel management */

Channel	*channel_by_id(কাঠামো ssh *, পূর্ণসংখ্যা);
Channel	*channel_by_remote_id(কাঠামো ssh *, u_int);
Channel	*channel_lookup(কাঠামো ssh *, পূর্ণসংখ্যা);
Channel *channel_new(কাঠামো ssh *, অক্ষর *, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা,
	    u_int, u_int, পূর্ণসংখ্যা, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);
শূন্য	 channel_set_fds(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা,
	    পূর্ণসংখ্যা, পূর্ণসংখ্যা, u_int);
শূন্য	 channel_set_tty(কাঠামো ssh *, Channel *);
শূন্য	 channel_free(কাঠামো ssh *, Channel *);
শূন্য	 channel_free_all(কাঠামো ssh *);
শূন্য	 channel_stop_listening(কাঠামো ssh *);
শূন্য	 channel_force_close(কাঠামো ssh *, Channel *, পূর্ণসংখ্যা);
শূন্য	 channel_set_xtype(কাঠামো ssh *, পূর্ণসংখ্যা, ধ্রুবক অক্ষর *);

শূন্য	 channel_send_open(কাঠামো ssh *, পূর্ণসংখ্যা);
শূন্য	 channel_request_start(কাঠামো ssh *, পূর্ণসংখ্যা, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);
শূন্য	 channel_register_cleanup(কাঠামো ssh *, পূর্ণসংখ্যা,
	    channel_callback_fn *, পূর্ণসংখ্যা);
শূন্য	 channel_register_open_confirm(কাঠামো ssh *, পূর্ণসংখ্যা,
	    channel_open_fn *, শূন্য *);
শূন্য	 channel_register_filter(কাঠামো ssh *, পূর্ণসংখ্যা, channel_infilter_fn *,
	    channel_outfilter_fn *, channel_filter_cleanup_fn *, শূন্য *);
শূন্য	 channel_register_status_confirm(কাঠামো ssh *, পূর্ণসংখ্যা,
	    channel_confirm_cb *, channel_confirm_abandon_cb *, শূন্য *);
শূন্য	 channel_cancel_cleanup(কাঠামো ssh *, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 channel_close_fd(কাঠামো ssh *, Channel *, পূর্ণসংখ্যা *);
শূন্য	 channel_send_window_changes(কাঠামো ssh *);
পূর্ণসংখ্যা	 channel_has_bulk(কাঠামো ssh *);
শূন্য	 channel_set_tcp_keepalives(কাঠামো ssh *, পূর্ণসংখ্যা);

/* channel inactivity timeouts */
শূন্য channel_add_timeout(কাঠামো ssh *, ধ্রুবক অক্ষর *, দ্বিগুণ);
শূন্য channel_clear_timeouts(কাঠামো ssh *);

/* mux proxy support */

পূর্ণসংখ্যা	 channel_proxy_downstream(কাঠামো ssh *, Channel *mc);
পূর্ণসংখ্যা	 channel_proxy_upstream(Channel *, পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);

/* protocol handler */

পূর্ণসংখ্যা	 channel_প্রবেশ_তথ্য(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
পূর্ণসংখ্যা	 channel_প্রবেশ_extended_তথ্য(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
পূর্ণসংখ্যা	 channel_প্রবেশ_ieof(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
পূর্ণসংখ্যা	 channel_প্রবেশ_oclose(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
পূর্ণসংখ্যা	 channel_প্রবেশ_open_confirmation(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
পূর্ণসংখ্যা	 channel_প্রবেশ_open_failure(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
পূর্ণসংখ্যা	 channel_প্রবেশ_window_adjust(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
পূর্ণসংখ্যা	 channel_প্রবেশ_status_confirm(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);

/* file descriptor handling (read/write) */
কাঠামো pollfd;
কাঠামো timespec;

শূন্য	 channel_prepare_poll(কাঠামো ssh *, কাঠামো pollfd **,
	    u_int *, u_int *, u_int, কাঠামো timespec *);
শূন্য	 channel_after_poll(কাঠামো ssh *, কাঠামো pollfd *, u_int);
পূর্ণসংখ্যা	 channel_output_poll(কাঠামো ssh *);

পূর্ণসংখ্যা      channel_not_very_much_buffered_তথ্য(কাঠামো ssh *);
শূন্য     channel_close_all(কাঠামো ssh *);
পূর্ণসংখ্যা      channel_still_open(কাঠামো ssh *);
পূর্ণসংখ্যা	 channel_tty_open(কাঠামো ssh *);
ধ্রুবক অক্ষর *channel_format_extended_usage(ধ্রুবক Channel *);
অক্ষর	*channel_open_message(কাঠামো ssh *);
শূন্য	 channel_report_open(কাঠামো ssh *, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 channel_find_open(কাঠামো ssh *);

/* tcp forwarding */
কাঠামো Forward;
কাঠামো ForwardOptions;
শূন্য	 channel_set_af(কাঠামো ssh *, পূর্ণসংখ্যা af);
শূন্য     channel_permit_all(কাঠামো ssh *, পূর্ণসংখ্যা);
শূন্য	 channel_add_permission(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা, অক্ষর *, পূর্ণসংখ্যা);
শূন্য	 channel_clear_permission(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
শূন্য	 channel_disable_admin(কাঠামো ssh *, পূর্ণসংখ্যা);
শূন্য	 channel_update_permission(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
Channel	*channel_connect_to_port(কাঠামো ssh *, ধ্রুবক অক্ষর *, u_short,
	    অক্ষর *, অক্ষর *, পূর্ণসংখ্যা *, ধ্রুবক অক্ষর **);
Channel *channel_connect_to_path(কাঠামো ssh *, ধ্রুবক অক্ষর *, অক্ষর *, অক্ষর *);
Channel	*channel_connect_stdio_fwd(কাঠামো ssh *, ধ্রুবক অক্ষর*,
	    পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
Channel	*channel_connect_by_listen_address(কাঠামো ssh *, ধ্রুবক অক্ষর *,
	    u_short, অক্ষর *, অক্ষর *);
Channel	*channel_connect_by_listen_path(কাঠামো ssh *, ধ্রুবক অক্ষর *,
	    অক্ষর *, অক্ষর *);
পূর্ণসংখ্যা	 channel_request_remote_forwarding(কাঠামো ssh *, কাঠামো Forward *);
পূর্ণসংখ্যা	 channel_setup_local_fwd_listener(কাঠামো ssh *, কাঠামো Forward *,
	    কাঠামো ForwardOptions *);
পূর্ণসংখ্যা	 channel_request_rforward_cancel(কাঠামো ssh *, কাঠামো Forward *);
পূর্ণসংখ্যা	 channel_setup_remote_fwd_listener(কাঠামো ssh *, কাঠামো Forward *,
	    পূর্ণসংখ্যা *, কাঠামো ForwardOptions *);
পূর্ণসংখ্যা	 channel_cancel_rport_listener(কাঠামো ssh *, কাঠামো Forward *);
পূর্ণসংখ্যা	 channel_cancel_lport_listener(কাঠামো ssh *, কাঠামো Forward *,
	    পূর্ণসংখ্যা, কাঠামো ForwardOptions *);
পূর্ণসংখ্যা	 permitopen_port(ধ্রুবক অক্ষর *);

/* x11 forwarding */

শূন্য	 channel_set_x11_refuse_time(কাঠামো ssh *, দ্বিগুণ);
পূর্ণসংখ্যা	 x11_connect_display(কাঠামো ssh *);
পূর্ণসংখ্যা	 x11_create_display_inet(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, u_int *, পূর্ণসংখ্যা **);
শূন্য	 x11_request_forwarding_with_spoofing(কাঠামো ssh *, পূর্ণসংখ্যা,
	    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);
পূর্ণসংখ্যা      x11_channel_used_recently(কাঠামো ssh *ssh);

/* channel close */

পূর্ণসংখ্যা	 chan_is_dead(কাঠামো ssh *, Channel *, পূর্ণসংখ্যা);
শূন্য	 chan_mark_dead(কাঠামো ssh *, Channel *);

/* agent forwarding */
শূন্য	 client_channel_request_agent_forwarding(কাঠামো ssh *, পূর্ণসংখ্যা);

/* channel events */

শূন্য	 chan_rcvd_oclose(কাঠামো ssh *, Channel *);
শূন্য	 chan_rcvd_eow(কাঠামো ssh *, Channel *);
শূন্য	 chan_read_failed(কাঠামো ssh *, Channel *);
শূন্য	 chan_ibuf_empty(কাঠামো ssh *, Channel *);
শূন্য	 chan_rcvd_ieof(কাঠামো ssh *, Channel *);
শূন্য	 chan_write_failed(কাঠামো ssh *, Channel *);
শূন্য	 chan_obuf_empty(কাঠামো ssh *, Channel *);

#endif
