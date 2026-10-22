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

संरचना ssh;
संरचना Channel;
प्रकारनिर्देश संरचना Channel Channel;
संरचना channel_connect;

प्रकारनिर्देश शून्य channel_open_fn(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क, शून्य *);
प्रकारनिर्देश शून्य channel_callback_fn(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क, शून्य *);
प्रकारनिर्देश पूर्णाङ्क channel_infilter_fn(संरचना ssh *, संरचना Channel *, वर्ण *, पूर्णाङ्क);
प्रकारनिर्देश शून्य channel_filter_cleanup_fn(संरचना ssh *, पूर्णाङ्क, शून्य *);
प्रकारनिर्देश u_char *channel_outfilter_fn(संरचना ssh *, संरचना Channel *,
    u_char **, size_t *);

/* Channel success/failure callbacks */
प्रकारनिर्देश शून्य channel_confirm_cb(संरचना ssh *, पूर्णाङ्क, संरचना Channel *, शून्य *);
प्रकारनिर्देश शून्य channel_confirm_abandon_cb(संरचना ssh *, संरचना Channel *, शून्य *);
संरचना channel_confirm {
	TAILQ_ENTRY(channel_confirm) entry;
	channel_confirm_cb *cb;
	channel_confirm_abandon_cb *abandon_cb;
	शून्य *ctx;
};
TAILQ_HEAD(channel_confirms, channel_confirm);

/* Callbacks for mux channels back into client-specific code */
प्रकारनिर्देश पूर्णाङ्क mux_callback_fn(संरचना ssh *, संरचना Channel *);

/*
 * NB. channel IDs on the wire and in c->remote_id are uint32, but local
 * channel IDs (e.g. c->self) only ever use the int32 subset of this range,
 * because we use local channel ID -1 for housekeeping. Remote channels have
 * a dedicated "have_remote_id" flag to indicate their validity.
 */

संरचना Channel {
	पूर्णाङ्क     type;		/* channel type/state */

	पूर्णाङ्क     self;		/* my own channel identifier */
	uint32_t remote_id;	/* channel identifier for remote peer */
	पूर्णाङ्क	have_remote_id;	/* non-zero if remote_id is valid */

	u_int   istate;		/* input from channel (state of receive half) */
	u_int   ostate;		/* output to channel  (state of transmit half) */
	पूर्णाङ्क     flags;		/* close sent/rcvd */
	पूर्णाङ्क     rfd;		/* read fd */
	पूर्णाङ्क     wfd;		/* write fd */
	पूर्णाङ्क     efd;		/* extended fd */
	पूर्णाङ्क     sock;		/* sock fd */
	u_int	io_want;	/* bitmask of SSH_CHAN_IO_* */
	u_int	io_ready;	/* bitmask of SSH_CHAN_IO_* */
	पूर्णाङ्क	pfds[4];	/* pollfd entries for rfd/wfd/efd/sock */
	पूर्णाङ्क     ctl_chan;	/* control channel (multiplexed connections) */
	uint32_t ctl_child_id;	/* child session for mux controllers */
	पूर्णाङ्क	have_ctl_child_id;/* non-zero if ctl_child_id is valid */
	पूर्णाङ्क     remote_has_tty;	/* remote side has a tty */
	पूर्णाङ्क     isatty;		/* rfd is a tty */
#ifdef _AIX
	पूर्णाङ्क     wfd_isatty;	/* wfd is a tty */
#endif
	पूर्णाङ्क	client_tty;	/* (client) TTY has been requested */
	पूर्णाङ्क     force_drain;	/* force close on iEOF */
	द्विगुण	notbefore;	/* Pause IO until deadline (time_t) */
	पूर्णाङ्क     delayed;	/* post-IO handlers for newly created
				 * channels are delayed until the first call
				 * to a matching pre-IO handler.
				 * this way post-IO handlers are not
				 * accidentally called if a FD gets reused */
	पूर्णाङ्क	restore_block;	/* fd mask to restore blocking status */
	पूर्णाङ्क	restore_flags[3];/* flags to restore */
	संरचना sshbuf *आदान;	/* data read from socket, to be sent over
				 * encrypted connection */
	संरचना sshbuf *output;	/* data received over encrypted connection for
				 * send on socket */
	संरचना sshbuf *extended;

	वर्ण    *path;
		/* path for unix domain sockets, or host name for forwards */
	पूर्णाङ्क     listening_port;	/* port being listened for forwards */
	वर्ण   *listening_addr;	/* addr being listened for forwards */
	पूर्णाङ्क     host_port;	/* remote port to connect for forwards */
	वर्ण   *remote_name;	/* remote hostname */

	u_int	remote_window;
	u_int	remote_maxpacket;
	u_int	local_window;
	u_int	local_window_exceeded;
	u_int	local_window_max;
	u_int	local_consumed;
	u_int	local_maxpacket;
	पूर्णाङ्क     extended_usage;
	पूर्णाङ्क	agent_new;	/* For agent listeners, use RFC 9987 requests */
	पूर्णाङ्क	single_connection;

	वर्ण   *ctype;		/* const type - NB. not freed on channel_free */
	वर्ण   *xctype;		/* extended type */
	पूर्णाङ्क	bulk;		/* channel is non-interactive */

	/* callback */
	channel_open_fn		*open_confirm;
	शून्य			*open_confirm_ctx;
	channel_callback_fn	*detach_user;
	पूर्णाङ्क			detach_close;
	संरचना channel_confirms	status_confirms;

	/* filter */
	channel_infilter_fn	*आदान_filter;
	channel_outfilter_fn	*output_filter;
	शून्य			*filter_ctx;
	channel_filter_cleanup_fn *filter_cleanup;

	/* keep boundaries */
	पूर्णाङ्क			datagram;

	/* non-blocking connect */
	संरचना channel_connect	*connect_ctx;

	/* multiplexing protocol hook, called for each packet received */
	mux_callback_fn		*mux_rcb;
	शून्य			*mux_ctx;
	पूर्णाङ्क			mux_pause;
	पूर्णाङ्क			mux_downstream_id;

	/* Inactivity timeouts */

	/* Last traffic seen for OPEN channels */
	द्विगुण			lastused;
	/* Inactivity timeout deadline in seconds (0 = no timeout) */
	द्विगुण			inactive_deadline;
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
#define CHAN_आदान_OPEN			0
#define CHAN_आदान_WAIT_DRAIN		1
#define CHAN_आदान_WAIT_OCLOSE		2
#define CHAN_आदान_CLOSED		3

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
#define CHAN_आदान_MAX	(16*1024*1024)

/* Hard limit on number of channels */
#define CHANNELS_MAX_CHANNELS	(16*1024)

/* check whether 'efd' is still in use */
#define CHANNEL_EFD_आदान_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_READ && \
	(c->efd != -1 || \
	sshbuf_len(c->extended) > 0))
#define CHANNEL_EFD_OUTPUT_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_WRITE && \
	c->efd != -1 && (!(c->flags & (CHAN_EOF_RCVD|CHAN_CLOSE_RCVD)) || \
	sshbuf_len(c->extended) > 0))

/* Add/remove channel management structures to/from SSH transport instance */
शून्य channel_init_channels(संरचना ssh *ssh);
शून्य channel_free_channels(संरचना ssh *ssh);

/* channel management */

Channel	*channel_by_id(संरचना ssh *, पूर्णाङ्क);
Channel	*channel_by_remote_id(संरचना ssh *, u_int);
Channel	*channel_lookup(संरचना ssh *, पूर्णाङ्क);
Channel *channel_new(संरचना ssh *, वर्ण *, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क,
	    u_int, u_int, पूर्णाङ्क, ध्रुव वर्ण *, पूर्णाङ्क);
शून्य	 channel_set_fds(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क,
	    पूर्णाङ्क, पूर्णाङ्क, u_int);
शून्य	 channel_set_tty(संरचना ssh *, Channel *);
शून्य	 channel_free(संरचना ssh *, Channel *);
शून्य	 channel_free_all(संरचना ssh *);
शून्य	 channel_stop_listening(संरचना ssh *);
शून्य	 channel_force_close(संरचना ssh *, Channel *, पूर्णाङ्क);
शून्य	 channel_set_xtype(संरचना ssh *, पूर्णाङ्क, ध्रुव वर्ण *);

शून्य	 channel_send_open(संरचना ssh *, पूर्णाङ्क);
शून्य	 channel_request_start(संरचना ssh *, पूर्णाङ्क, ध्रुव वर्ण *, पूर्णाङ्क);
शून्य	 channel_register_cleanup(संरचना ssh *, पूर्णाङ्क,
	    channel_callback_fn *, पूर्णाङ्क);
शून्य	 channel_register_open_confirm(संरचना ssh *, पूर्णाङ्क,
	    channel_open_fn *, शून्य *);
शून्य	 channel_register_filter(संरचना ssh *, पूर्णाङ्क, channel_infilter_fn *,
	    channel_outfilter_fn *, channel_filter_cleanup_fn *, शून्य *);
शून्य	 channel_register_status_confirm(संरचना ssh *, पूर्णाङ्क,
	    channel_confirm_cb *, channel_confirm_abandon_cb *, शून्य *);
शून्य	 channel_cancel_cleanup(संरचना ssh *, पूर्णाङ्क);
पूर्णाङ्क	 channel_close_fd(संरचना ssh *, Channel *, पूर्णाङ्क *);
शून्य	 channel_send_window_changes(संरचना ssh *);
पूर्णाङ्क	 channel_has_bulk(संरचना ssh *);
शून्य	 channel_set_tcp_keepalives(संरचना ssh *, पूर्णाङ्क);

/* channel inactivity timeouts */
शून्य channel_add_timeout(संरचना ssh *, ध्रुव वर्ण *, द्विगुण);
शून्य channel_clear_timeouts(संरचना ssh *);

/* mux proxy support */

पूर्णाङ्क	 channel_proxy_downstream(संरचना ssh *, Channel *mc);
पूर्णाङ्क	 channel_proxy_upstream(Channel *, पूर्णाङ्क, uint32_t, संरचना ssh *);

/* protocol handler */

पूर्णाङ्क	 channel_आदान_data(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 channel_आदान_extended_data(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 channel_आदान_ieof(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 channel_आदान_oclose(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 channel_आदान_open_confirmation(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 channel_आदान_open_failure(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 channel_आदान_window_adjust(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 channel_आदान_status_confirm(पूर्णाङ्क, uint32_t, संरचना ssh *);

/* file descriptor handling (read/write) */
संरचना pollfd;
संरचना timespec;

शून्य	 channel_prepare_poll(संरचना ssh *, संरचना pollfd **,
	    u_int *, u_int *, u_int, संरचना timespec *);
शून्य	 channel_after_poll(संरचना ssh *, संरचना pollfd *, u_int);
पूर्णाङ्क	 channel_output_poll(संरचना ssh *);

पूर्णाङ्क      channel_not_very_much_buffered_data(संरचना ssh *);
शून्य     channel_close_all(संरचना ssh *);
पूर्णाङ्क      channel_still_open(संरचना ssh *);
पूर्णाङ्क	 channel_tty_open(संरचना ssh *);
ध्रुव वर्ण *channel_format_extended_usage(ध्रुव Channel *);
वर्ण	*channel_open_message(संरचना ssh *);
शून्य	 channel_report_open(संरचना ssh *, पूर्णाङ्क);
पूर्णाङ्क	 channel_find_open(संरचना ssh *);

/* tcp forwarding */
संरचना Forward;
संरचना ForwardOptions;
शून्य	 channel_set_af(संरचना ssh *, पूर्णाङ्क af);
शून्य     channel_permit_all(संरचना ssh *, पूर्णाङ्क);
शून्य	 channel_add_permission(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क, वर्ण *, पूर्णाङ्क);
शून्य	 channel_clear_permission(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क);
शून्य	 channel_disable_admin(संरचना ssh *, पूर्णाङ्क);
शून्य	 channel_update_permission(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क);
Channel	*channel_connect_to_port(संरचना ssh *, ध्रुव वर्ण *, u_short,
	    वर्ण *, वर्ण *, पूर्णाङ्क *, ध्रुव वर्ण **);
Channel *channel_connect_to_path(संरचना ssh *, ध्रुव वर्ण *, वर्ण *, वर्ण *);
Channel	*channel_connect_stdio_fwd(संरचना ssh *, ध्रुव वर्ण*,
	    पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क);
Channel	*channel_connect_by_listen_address(संरचना ssh *, ध्रुव वर्ण *,
	    u_short, वर्ण *, वर्ण *);
Channel	*channel_connect_by_listen_path(संरचना ssh *, ध्रुव वर्ण *,
	    वर्ण *, वर्ण *);
पूर्णाङ्क	 channel_request_remote_forwarding(संरचना ssh *, संरचना Forward *);
पूर्णाङ्क	 channel_setup_local_fwd_listener(संरचना ssh *, संरचना Forward *,
	    संरचना ForwardOptions *);
पूर्णाङ्क	 channel_request_rforward_cancel(संरचना ssh *, संरचना Forward *);
पूर्णाङ्क	 channel_setup_remote_fwd_listener(संरचना ssh *, संरचना Forward *,
	    पूर्णाङ्क *, संरचना ForwardOptions *);
पूर्णाङ्क	 channel_cancel_rport_listener(संरचना ssh *, संरचना Forward *);
पूर्णाङ्क	 channel_cancel_lport_listener(संरचना ssh *, संरचना Forward *,
	    पूर्णाङ्क, संरचना ForwardOptions *);
पूर्णाङ्क	 permitopen_port(ध्रुव वर्ण *);

/* x11 forwarding */

शून्य	 channel_set_x11_refuse_time(संरचना ssh *, द्विगुण);
पूर्णाङ्क	 x11_connect_display(संरचना ssh *);
पूर्णाङ्क	 x11_create_display_inet(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, u_int *, पूर्णाङ्क **);
शून्य	 x11_request_forwarding_with_spoofing(संरचना ssh *, पूर्णाङ्क,
	    ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क);
पूर्णाङ्क      x11_channel_used_recently(संरचना ssh *ssh);

/* channel close */

पूर्णाङ्क	 chan_is_dead(संरचना ssh *, Channel *, पूर्णाङ्क);
शून्य	 chan_mark_dead(संरचना ssh *, Channel *);

/* agent forwarding */
शून्य	 client_channel_request_agent_forwarding(संरचना ssh *, पूर्णाङ्क);

/* channel events */

शून्य	 chan_rcvd_oclose(संरचना ssh *, Channel *);
शून्य	 chan_rcvd_eow(संरचना ssh *, Channel *);
शून्य	 chan_read_failed(संरचना ssh *, Channel *);
शून्य	 chan_ibuf_empty(संरचना ssh *, Channel *);
शून्य	 chan_rcvd_ieof(संरचना ssh *, Channel *);
शून्य	 chan_write_failed(संरचना ssh *, Channel *);
शून्य	 chan_obuf_empty(संरचना ssh *, Channel *);

#endif
