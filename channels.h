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

#अगर_अघोषित CHANNEL_H
#घोषणा CHANNEL_H

/* Definitions for channel types. */
#घोषणा SSH_CHANNEL_X11_LISTENER	1	/* Listening for inet X11 conn. */
#घोषणा SSH_CHANNEL_PORT_LISTENER	2	/* Listening on a port. */
#घोषणा SSH_CHANNEL_OPENING		3	/* waiting for confirmation */
#घोषणा SSH_CHANNEL_OPEN		4	/* normal open two-way channel */
#घोषणा SSH_CHANNEL_CLOSED		5	/* waiting for close confirmation */
#घोषणा SSH_CHANNEL_AUTH_SOCKET		6	/* authentication socket */
#घोषणा SSH_CHANNEL_X11_OPEN		7	/* reading first X11 packet */
#घोषणा SSH_CHANNEL_LARVAL		10	/* larval session */
#घोषणा SSH_CHANNEL_RPORT_LISTENER	11	/* Listening to a R-style port  */
#घोषणा SSH_CHANNEL_CONNECTING		12
#घोषणा SSH_CHANNEL_DYNAMIC		13
#घोषणा SSH_CHANNEL_ZOMBIE		14	/* Almost dead. */
#घोषणा SSH_CHANNEL_MUX_LISTENER	15	/* Listener for mux conn. */
#घोषणा SSH_CHANNEL_MUX_CLIENT		16	/* Conn. to mux client */
#घोषणा SSH_CHANNEL_ABANDONED		17	/* Abandoned session, eg mux */
#घोषणा SSH_CHANNEL_UNIX_LISTENER	18	/* Listening on a domain socket. */
#घोषणा SSH_CHANNEL_RUNIX_LISTENER	19	/* Listening to a R-style domain socket. */
#घोषणा SSH_CHANNEL_MUX_PROXY		20	/* proxy channel for mux-client */
#घोषणा SSH_CHANNEL_RDYNAMIC_OPEN	21	/* reverse SOCKS, parsing request */
#घोषणा SSH_CHANNEL_RDYNAMIC_FINISH	22	/* reverse SOCKS, finishing connect */
#घोषणा SSH_CHANNEL_MAX_TYPE		23

#घोषणा CHANNEL_CANCEL_PORT_STATIC	-1

/* nonblocking flags for channel_new */
#घोषणा CHANNEL_NONBLOCK_LEAVE	0 /* don't modify non-blocking state */
#घोषणा CHANNEL_NONBLOCK_SET	1 /* set non-blocking state */
#घोषणा CHANNEL_NONBLOCK_STDIO	2 /* set non-blocking and restore on close */

/* c->restore_block mask flags */
#घोषणा CHANNEL_RESTORE_RFD	0x01
#घोषणा CHANNEL_RESTORE_WFD	0x02
#घोषणा CHANNEL_RESTORE_EFD	0x04

/* TCP forwarding */
#घोषणा FORWARD_DENY		0
#घोषणा FORWARD_REMOTE		(1)
#घोषणा FORWARD_LOCAL		(1<<1)
#घोषणा FORWARD_ALLOW		(FORWARD_REMOTE|FORWARD_LOCAL)

#घोषणा FORWARD_ADM		0x100
#घोषणा FORWARD_USER		0x101

/* default pattern-lists used to classify channel types as bulk */
#घोषणा CHANNEL_BULK_TTY	""
#घोषणा CHANNEL_BULK_NOTTY	"direct-*,forwarded-*,dynamic-*," \
				"tun-*,x11-*,session*,stdio-forward"

काष्ठा ssh;
काष्ठा Channel;
प्रकार काष्ठा Channel Channel;
काष्ठा channel_connect;

प्रकार व्योम channel_open_fn(काष्ठा ssh *, पूर्णांक, पूर्णांक, व्योम *);
प्रकार व्योम channel_callback_fn(काष्ठा ssh *, पूर्णांक, पूर्णांक, व्योम *);
प्रकार पूर्णांक channel_infilter_fn(काष्ठा ssh *, काष्ठा Channel *, अक्षर *, पूर्णांक);
प्रकार व्योम channel_filter_cleanup_fn(काष्ठा ssh *, पूर्णांक, व्योम *);
प्रकार u_char *channel_outfilter_fn(काष्ठा ssh *, काष्ठा Channel *,
    u_char **, माप_प्रकार *);

/* Channel success/failure callbacks */
प्रकार व्योम channel_confirm_cb(काष्ठा ssh *, पूर्णांक, काष्ठा Channel *, व्योम *);
प्रकार व्योम channel_confirm_abandon_cb(काष्ठा ssh *, काष्ठा Channel *, व्योम *);
काष्ठा channel_confirm {
	TAILQ_ENTRY(channel_confirm) entry;
	channel_confirm_cb *cb;
	channel_confirm_abandon_cb *abandon_cb;
	व्योम *ctx;
};
TAILQ_HEAD(channel_confirms, channel_confirm);

/* Callbacks for mux channels back into client-specific code */
प्रकार पूर्णांक mux_callback_fn(काष्ठा ssh *, काष्ठा Channel *);

/*
 * NB. channel IDs on the wire and in c->remote_id are uint32, but local
 * channel IDs (e.g. c->self) only ever use the int32 subset of this range,
 * because we use local channel ID -1 for housekeeping. Remote channels have
 * a dedicated "have_remote_id" flag to indicate their validity.
 */

काष्ठा Channel {
	पूर्णांक     type;		/* channel type/state */

	पूर्णांक     self;		/* my own channel identifier */
	uint32_t remote_id;	/* channel identifier for remote peer */
	पूर्णांक	have_remote_id;	/* non-zero if remote_id is valid */

	u_int   istate;		/* input from channel (state of receive half) */
	u_int   ostate;		/* output to channel  (state of transmit half) */
	पूर्णांक     flags;		/* close sent/rcvd */
	पूर्णांक     rfd;		/* read fd */
	पूर्णांक     wfd;		/* write fd */
	पूर्णांक     efd;		/* extended fd */
	पूर्णांक     sock;		/* sock fd */
	u_int	io_want;	/* bitmask of SSH_CHAN_IO_* */
	u_int	io_ready;	/* bitmask of SSH_CHAN_IO_* */
	पूर्णांक	pfds[4];	/* pollfd entries for rfd/wfd/efd/sock */
	पूर्णांक     ctl_chan;	/* control channel (multiplexed connections) */
	uint32_t ctl_child_id;	/* child session for mux controllers */
	पूर्णांक	have_ctl_child_id;/* non-zero if ctl_child_id is valid */
	पूर्णांक     remote_has_tty;	/* remote side has a tty */
	पूर्णांक     isatty;		/* rfd is a tty */
#अगर_घोषित _AIX
	पूर्णांक     wfd_isatty;	/* wfd is a tty */
#पूर्ण_अगर
	पूर्णांक	client_tty;	/* (client) TTY has been requested */
	पूर्णांक     force_drain;	/* force close on iEOF */
	द्विगुन	notbefore;	/* Pause IO until deadline (time_t) */
	पूर्णांक     delayed;	/* post-IO handlers for newly created
				 * channels are delayed until the first call
				 * to a matching pre-IO handler.
				 * this way post-IO handlers are not
				 * accidentally called if a FD gets reused */
	पूर्णांक	restore_block;	/* fd mask to restore blocking status */
	पूर्णांक	restore_flags[3];/* flags to restore */
	काष्ठा sshbuf *निवेश;	/* data read from socket, to be sent over
				 * encrypted connection */
	काष्ठा sshbuf *output;	/* data received over encrypted connection for
				 * send on socket */
	काष्ठा sshbuf *extended;

	अक्षर    *path;
		/* path for unix domain sockets, or host name for forwards */
	पूर्णांक     listening_port;	/* port being listened for forwards */
	अक्षर   *listening_addr;	/* addr being listened for forwards */
	पूर्णांक     host_port;	/* remote port to connect for forwards */
	अक्षर   *remote_name;	/* remote hostname */

	u_int	remote_window;
	u_int	remote_maxpacket;
	u_int	local_window;
	u_int	local_window_exceeded;
	u_int	local_window_max;
	u_int	local_consumed;
	u_int	local_maxpacket;
	पूर्णांक     extended_usage;
	पूर्णांक	agent_new;	/* For agent listeners, use RFC 9987 requests */
	पूर्णांक	single_connection;

	अक्षर   *ctype;		/* const type - NB. not freed on channel_free */
	अक्षर   *xctype;		/* extended type */
	पूर्णांक	bulk;		/* channel is non-interactive */

	/* callback */
	channel_open_fn		*open_confirm;
	व्योम			*open_confirm_ctx;
	channel_callback_fn	*detach_user;
	पूर्णांक			detach_close;
	काष्ठा channel_confirms	status_confirms;

	/* filter */
	channel_infilter_fn	*निवेश_filter;
	channel_outfilter_fn	*output_filter;
	व्योम			*filter_ctx;
	channel_filter_cleanup_fn *filter_cleanup;

	/* keep boundaries */
	पूर्णांक			datagram;

	/* non-blocking connect */
	काष्ठा channel_connect	*connect_ctx;

	/* multiplexing protocol hook, called for each packet received */
	mux_callback_fn		*mux_rcb;
	व्योम			*mux_ctx;
	पूर्णांक			mux_pause;
	पूर्णांक			mux_downstream_id;

	/* Inactivity timeouts */

	/* Last traffic seen for OPEN channels */
	द्विगुन			lastused;
	/* Inactivity timeout deadline in seconds (0 = no timeout) */
	द्विगुन			inactive_deadline;
};

#घोषणा CHAN_EXTENDED_IGNORE		0
#घोषणा CHAN_EXTENDED_READ		1
#घोषणा CHAN_EXTENDED_WRITE		2

/* default window/packet sizes for tcp/x11-fwd-channel */
#घोषणा CHAN_SES_PACKET_DEFAULT	(32*1024)
#घोषणा CHAN_SES_WINDOW_DEFAULT	(64*CHAN_SES_PACKET_DEFAULT)
#घोषणा CHAN_TCP_PACKET_DEFAULT	(32*1024)
#घोषणा CHAN_TCP_WINDOW_DEFAULT	(64*CHAN_TCP_PACKET_DEFAULT)
#घोषणा CHAN_X11_PACKET_DEFAULT	(16*1024)
#घोषणा CHAN_X11_WINDOW_DEFAULT	(4*CHAN_X11_PACKET_DEFAULT)

/* possible input states */
#घोषणा CHAN_निवेश_OPEN			0
#घोषणा CHAN_निवेश_WAIT_DRAIN		1
#घोषणा CHAN_निवेश_WAIT_OCLOSE		2
#घोषणा CHAN_निवेश_CLOSED		3

/* possible output states */
#घोषणा CHAN_OUTPUT_OPEN		0
#घोषणा CHAN_OUTPUT_WAIT_DRAIN		1
#घोषणा CHAN_OUTPUT_WAIT_IEOF		2
#घोषणा CHAN_OUTPUT_CLOSED		3

#घोषणा CHAN_CLOSE_SENT			0x01
#घोषणा CHAN_CLOSE_RCVD			0x02
#घोषणा CHAN_EOF_SENT			0x04
#घोषणा CHAN_EOF_RCVD			0x08
#घोषणा CHAN_LOCAL			0x10

/* file descriptor events */
#घोषणा SSH_CHAN_IO_RFD			0x01
#घोषणा SSH_CHAN_IO_WFD			0x02
#घोषणा SSH_CHAN_IO_EFD_R		0x04
#घोषणा SSH_CHAN_IO_EFD_W		0x08
#घोषणा SSH_CHAN_IO_EFD			(SSH_CHAN_IO_EFD_R|SSH_CHAN_IO_EFD_W)
#घोषणा SSH_CHAN_IO_SOCK_R		0x10
#घोषणा SSH_CHAN_IO_SOCK_W		0x20
#घोषणा SSH_CHAN_IO_SOCK		(SSH_CHAN_IO_SOCK_R|SSH_CHAN_IO_SOCK_W)

/* Read buffer size */
#घोषणा CHAN_RBUF	(16*1024)

/* Maximum size for direct reads to buffers */
#घोषणा CHANNEL_MAX_READ	CHAN_SES_PACKET_DEFAULT

/* Maximum channel input buffer size */
#घोषणा CHAN_निवेश_MAX	(16*1024*1024)

/* Hard limit on number of channels */
#घोषणा CHANNELS_MAX_CHANNELS	(16*1024)

/* check whether 'efd' is still in use */
#घोषणा CHANNEL_EFD_निवेश_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_READ && \
	(c->efd != -1 || \
	sshbuf_len(c->extended) > 0))
#घोषणा CHANNEL_EFD_OUTPUT_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_WRITE && \
	c->efd != -1 && (!(c->flags & (CHAN_EOF_RCVD|CHAN_CLOSE_RCVD)) || \
	sshbuf_len(c->extended) > 0))

/* Add/remove channel management structures to/from SSH transport instance */
व्योम channel_init_channels(काष्ठा ssh *ssh);
व्योम channel_free_channels(काष्ठा ssh *ssh);

/* channel management */

Channel	*channel_by_id(काष्ठा ssh *, पूर्णांक);
Channel	*channel_by_remote_id(काष्ठा ssh *, u_int);
Channel	*channel_lookup(काष्ठा ssh *, पूर्णांक);
Channel *channel_new(काष्ठा ssh *, अक्षर *, पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक,
	    u_int, u_int, पूर्णांक, स्थिर अक्षर *, पूर्णांक);
व्योम	 channel_set_fds(काष्ठा ssh *, पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक,
	    पूर्णांक, पूर्णांक, u_int);
व्योम	 channel_set_tty(काष्ठा ssh *, Channel *);
व्योम	 channel_free(काष्ठा ssh *, Channel *);
व्योम	 channel_free_all(काष्ठा ssh *);
व्योम	 channel_stop_listening(काष्ठा ssh *);
व्योम	 channel_force_close(काष्ठा ssh *, Channel *, पूर्णांक);
व्योम	 channel_set_xtype(काष्ठा ssh *, पूर्णांक, स्थिर अक्षर *);

व्योम	 channel_send_open(काष्ठा ssh *, पूर्णांक);
व्योम	 channel_request_start(काष्ठा ssh *, पूर्णांक, स्थिर अक्षर *, पूर्णांक);
व्योम	 channel_register_cleanup(काष्ठा ssh *, पूर्णांक,
	    channel_callback_fn *, पूर्णांक);
व्योम	 channel_register_open_confirm(काष्ठा ssh *, पूर्णांक,
	    channel_open_fn *, व्योम *);
व्योम	 channel_register_filter(काष्ठा ssh *, पूर्णांक, channel_infilter_fn *,
	    channel_outfilter_fn *, channel_filter_cleanup_fn *, व्योम *);
व्योम	 channel_register_status_confirm(काष्ठा ssh *, पूर्णांक,
	    channel_confirm_cb *, channel_confirm_abandon_cb *, व्योम *);
व्योम	 channel_cancel_cleanup(काष्ठा ssh *, पूर्णांक);
पूर्णांक	 channel_close_fd(काष्ठा ssh *, Channel *, पूर्णांक *);
व्योम	 channel_send_window_changes(काष्ठा ssh *);
पूर्णांक	 channel_has_bulk(काष्ठा ssh *);
व्योम	 channel_set_tcp_keepalives(काष्ठा ssh *, पूर्णांक);

/* channel inactivity timeouts */
व्योम channel_add_timeout(काष्ठा ssh *, स्थिर अक्षर *, द्विगुन);
व्योम channel_clear_timeouts(काष्ठा ssh *);

/* mux proxy support */

पूर्णांक	 channel_proxy_downstream(काष्ठा ssh *, Channel *mc);
पूर्णांक	 channel_proxy_upstream(Channel *, पूर्णांक, uint32_t, काष्ठा ssh *);

/* protocol handler */

पूर्णांक	 channel_निवेश_तथ्य(पूर्णांक, uint32_t, काष्ठा ssh *);
पूर्णांक	 channel_निवेश_extended_तथ्य(पूर्णांक, uint32_t, काष्ठा ssh *);
पूर्णांक	 channel_निवेश_ieof(पूर्णांक, uint32_t, काष्ठा ssh *);
पूर्णांक	 channel_निवेश_oclose(पूर्णांक, uint32_t, काष्ठा ssh *);
पूर्णांक	 channel_निवेश_open_confirmation(पूर्णांक, uint32_t, काष्ठा ssh *);
पूर्णांक	 channel_निवेश_open_failure(पूर्णांक, uint32_t, काष्ठा ssh *);
पूर्णांक	 channel_निवेश_window_adjust(पूर्णांक, uint32_t, काष्ठा ssh *);
पूर्णांक	 channel_निवेश_status_confirm(पूर्णांक, uint32_t, काष्ठा ssh *);

/* file descriptor handling (read/write) */
काष्ठा pollfd;
काष्ठा timespec;

व्योम	 channel_prepare_poll(काष्ठा ssh *, काष्ठा pollfd **,
	    u_int *, u_int *, u_int, काष्ठा timespec *);
व्योम	 channel_after_poll(काष्ठा ssh *, काष्ठा pollfd *, u_int);
पूर्णांक	 channel_output_poll(काष्ठा ssh *);

पूर्णांक      channel_not_very_much_buffered_तथ्य(काष्ठा ssh *);
व्योम     channel_close_all(काष्ठा ssh *);
पूर्णांक      channel_still_open(काष्ठा ssh *);
पूर्णांक	 channel_tty_open(काष्ठा ssh *);
स्थिर अक्षर *channel_format_extended_usage(स्थिर Channel *);
अक्षर	*channel_open_message(काष्ठा ssh *);
व्योम	 channel_report_open(काष्ठा ssh *, पूर्णांक);
पूर्णांक	 channel_find_open(काष्ठा ssh *);

/* tcp forwarding */
काष्ठा Forward;
काष्ठा ForwardOptions;
व्योम	 channel_set_af(काष्ठा ssh *, पूर्णांक af);
व्योम     channel_permit_all(काष्ठा ssh *, पूर्णांक);
व्योम	 channel_add_permission(काष्ठा ssh *, पूर्णांक, पूर्णांक, अक्षर *, पूर्णांक);
व्योम	 channel_clear_permission(काष्ठा ssh *, पूर्णांक, पूर्णांक);
व्योम	 channel_disable_admin(काष्ठा ssh *, पूर्णांक);
व्योम	 channel_update_permission(काष्ठा ssh *, पूर्णांक, पूर्णांक);
Channel	*channel_connect_to_port(काष्ठा ssh *, स्थिर अक्षर *, u_short,
	    अक्षर *, अक्षर *, पूर्णांक *, स्थिर अक्षर **);
Channel *channel_connect_to_path(काष्ठा ssh *, स्थिर अक्षर *, अक्षर *, अक्षर *);
Channel	*channel_connect_stdio_fwd(काष्ठा ssh *, स्थिर अक्षर*,
	    पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक);
Channel	*channel_connect_by_listen_address(काष्ठा ssh *, स्थिर अक्षर *,
	    u_short, अक्षर *, अक्षर *);
Channel	*channel_connect_by_listen_path(काष्ठा ssh *, स्थिर अक्षर *,
	    अक्षर *, अक्षर *);
पूर्णांक	 channel_request_remote_forwarding(काष्ठा ssh *, काष्ठा Forward *);
पूर्णांक	 channel_setup_local_fwd_listener(काष्ठा ssh *, काष्ठा Forward *,
	    काष्ठा ForwardOptions *);
पूर्णांक	 channel_request_rforward_cancel(काष्ठा ssh *, काष्ठा Forward *);
पूर्णांक	 channel_setup_remote_fwd_listener(काष्ठा ssh *, काष्ठा Forward *,
	    पूर्णांक *, काष्ठा ForwardOptions *);
पूर्णांक	 channel_cancel_rport_listener(काष्ठा ssh *, काष्ठा Forward *);
पूर्णांक	 channel_cancel_lport_listener(काष्ठा ssh *, काष्ठा Forward *,
	    पूर्णांक, काष्ठा ForwardOptions *);
पूर्णांक	 permitopen_port(स्थिर अक्षर *);

/* x11 forwarding */

व्योम	 channel_set_x11_refuse_time(काष्ठा ssh *, द्विगुन);
पूर्णांक	 x11_connect_display(काष्ठा ssh *);
पूर्णांक	 x11_create_display_inet(काष्ठा ssh *, पूर्णांक, पूर्णांक, पूर्णांक, u_int *, पूर्णांक **);
व्योम	 x11_request_forwarding_with_spoofing(काष्ठा ssh *, पूर्णांक,
	    स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *, पूर्णांक);
पूर्णांक      x11_channel_used_recently(काष्ठा ssh *ssh);

/* channel close */

पूर्णांक	 chan_is_dead(काष्ठा ssh *, Channel *, पूर्णांक);
व्योम	 chan_mark_dead(काष्ठा ssh *, Channel *);

/* agent forwarding */
व्योम	 client_channel_request_agent_forwarding(काष्ठा ssh *, पूर्णांक);

/* channel events */

व्योम	 chan_rcvd_oclose(काष्ठा ssh *, Channel *);
व्योम	 chan_rcvd_eow(काष्ठा ssh *, Channel *);
व्योम	 chan_read_failed(काष्ठा ssh *, Channel *);
व्योम	 chan_ibuf_empty(काष्ठा ssh *, Channel *);
व्योम	 chan_rcvd_ieof(काष्ठा ssh *, Channel *);
व्योम	 chan_write_failed(काष्ठा ssh *, Channel *);
व्योम	 chan_obuf_empty(काष्ठा ssh *, Channel *);

#पूर्ण_अगर
