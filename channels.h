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

#यदि_अपरिभाषितम् CHANNEL_H
#परिभाषय CHANNEL_H

/* Definitions for channel types. */
#परिभाषय SSH_CHANNEL_X11_LISTENER	1	/* Listening for inet X11 conn. */
#परिभाषय SSH_CHANNEL_पत्तनम्_LISTENER	2	/* Listening on a port. */
#परिभाषय SSH_CHANNEL_OPENING		3	/* waiting for confirmation */
#परिभाषय SSH_CHANNEL_OPEN		4	/* normal open two-way channel */
#परिभाषय SSH_CHANNEL_CLOSED		5	/* waiting for close confirmation */
#परिभाषय SSH_CHANNEL_AUTH_SOCKET		6	/* authentication socket */
#परिभाषय SSH_CHANNEL_X11_OPEN		7	/* reading first X11 packet */
#परिभाषय SSH_CHANNEL_LARVAL		10	/* larval session */
#परिभाषय SSH_CHANNEL_RPORT_LISTENER	11	/* Listening to a R-style port  */
#परिभाषय SSH_CHANNEL_CONNECTING		12
#परिभाषय SSH_CHANNEL_DYNAMIC		13
#परिभाषय SSH_CHANNEL_ZOMBIE		14	/* Almost dead. */
#परिभाषय SSH_CHANNEL_MUX_LISTENER	15	/* Listener for mux conn. */
#परिभाषय SSH_CHANNEL_MUX_CLIENT		16	/* Conn. to mux client */
#परिभाषय SSH_CHANNEL_ABANDONED		17	/* Abandoned session, eg mux */
#परिभाषय SSH_CHANNEL_UNIX_LISTENER	18	/* Listening on a domain socket. */
#परिभाषय SSH_CHANNEL_RUNIX_LISTENER	19	/* Listening to a R-style domain socket. */
#परिभाषय SSH_CHANNEL_MUX_PROXY		20	/* proxy channel for mux-client */
#परिभाषय SSH_CHANNEL_RDYNAMIC_OPEN	21	/* reverse SOCKS, parsing request */
#परिभाषय SSH_CHANNEL_RDYNAMIC_FINISH	22	/* reverse SOCKS, finishing connect */
#परिभाषय SSH_CHANNEL_MAX_TYPE		23

#परिभाषय CHANNEL_CANCEL_पत्तनम्_STATIC	-1

/* nonblocking flags for channel_new */
#परिभाषय CHANNEL_NONBLOCK_LEAVE	0 /* don't modify non-blocking state */
#परिभाषय CHANNEL_NONBLOCK_समुच्चयः	1 /* set non-blocking state */
#परिभाषय CHANNEL_NONBLOCK_STDIO	2 /* set non-blocking and restore on close */

/* c->restore_block mask flags */
#परिभाषय CHANNEL_RESTORE_RFD	0x01
#परिभाषय CHANNEL_RESTORE_WFD	0x02
#परिभाषय CHANNEL_RESTORE_EFD	0x04

/* TCP forwarding */
#परिभाषय FORWARD_DENY		0
#परिभाषय FORWARD_REMOTE		(1)
#परिभाषय FORWARD_LOCAL		(1<<1)
#परिभाषय FORWARD_ALLOW		(FORWARD_REMOTE|FORWARD_LOCAL)

#परिभाषय FORWARD_ADM		0x100
#परिभाषय FORWARD_USER		0x101

/* default pattern-lists used to classify channel types as bulk */
#परिभाषय CHANNEL_BULK_TTY	""
#परिभाषय CHANNEL_BULK_NOTTY	"direct-*,forwarded-*,dynamic-*," \
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
    u_char **, आकार_t *);

/* Channel success/failure callbacks */
प्रकारनिर्देश शून्य channel_confirm_cb(संरचना ssh *, पूर्णाङ्क, संरचना Channel *, शून्य *);
प्रकारनिर्देश शून्य channel_confirm_abandon_cb(संरचना ssh *, संरचना Channel *, शून्य *);
संरचना channel_confirm {
	TAILQ_ENTRY(channel_confirm) प्रविष्टिः;
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
#यदि_परिभाषितम् _AIX
	पूर्णाङ्क     wfd_isatty;	/* wfd is a tty */
#यदि_अन्तः
	पूर्णाङ्क	client_tty;	/* (client) TTY has been requested */
	पूर्णाङ्क     force_drain;	/* force close on iEOF */
	द्विगुण	notbefore;	/* Pause IO until deadline (time_t) */
	पूर्णाङ्क     delayed;	/* post-IO handlers for newly created
				 * channels are delayed until the first call
				 * to a matching pre-IO handler.
				 * this way post-IO handlers are not
				 * accidentally called if a FD gets reused */
	पूर्णाङ्क	restore_खण्डम्;	/* fd mask to restore blocking status */
	पूर्णाङ्क	restore_flags[3];/* flags to restore */
	संरचना sshbuf *निवेशः;	/* data read from socket, to be sent over
				 * encrypted connection */
	संरचना sshbuf *output;	/* data received over encrypted connection for
				 * send on socket */
	संरचना sshbuf *extended;

	वर्ण    *मार्गः;
		/* path for unix domain sockets, or host name for forwards */
	पूर्णाङ्क     listening_पत्तनम्;	/* port being listened for forwards */
	वर्ण   *listening_addr;	/* addr being listened for forwards */
	पूर्णाङ्क     host_पत्तनम्;	/* remote port to connect for forwards */
	वर्ण   *remote_name;	/* remote hostname */

	u_int	remote_गवाक्षः;
	u_int	remote_maxpacket;
	u_int	local_गवाक्षः;
	u_int	local_गवाक्षः_exceeded;
	u_int	local_गवाक्षः_max;
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
	संरचना channel_confirms	स्थितिः_confirms;

	/* filter */
	channel_infilter_fn	*निवेशः_filter;
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

#परिभाषय CHAN_EXTENDED_IGNORE		0
#परिभाषय CHAN_EXTENDED_READ		1
#परिभाषय CHAN_EXTENDED_WRITE		2

/* default window/packet sizes for tcp/x11-fwd-channel */
#परिभाषय CHAN_SES_PACKET_DEFAULT	(32*1024)
#परिभाषय CHAN_SES_गवाक्षः_DEFAULT	(64*CHAN_SES_PACKET_DEFAULT)
#परिभाषय CHAN_TCP_PACKET_DEFAULT	(32*1024)
#परिभाषय CHAN_TCP_गवाक्षः_DEFAULT	(64*CHAN_TCP_PACKET_DEFAULT)
#परिभाषय CHAN_X11_PACKET_DEFAULT	(16*1024)
#परिभाषय CHAN_X11_गवाक्षः_DEFAULT	(4*CHAN_X11_PACKET_DEFAULT)

/* possible input states */
#परिभाषय CHAN_निवेशः_OPEN			0
#परिभाषय CHAN_निवेशः_WAIT_DRAIN		1
#परिभाषय CHAN_निवेशः_WAIT_OCLOSE		2
#परिभाषय CHAN_निवेशः_CLOSED		3

/* possible output states */
#परिभाषय CHAN_OUTPUT_OPEN		0
#परिभाषय CHAN_OUTPUT_WAIT_DRAIN		1
#परिभाषय CHAN_OUTPUT_WAIT_IEOF		2
#परिभाषय CHAN_OUTPUT_CLOSED		3

#परिभाषय CHAN_CLOSE_प्रेषितम्			0x01
#परिभाषय CHAN_CLOSE_RCVD			0x02
#परिभाषय CHAN_EOF_प्रेषितम्			0x04
#परिभाषय CHAN_EOF_RCVD			0x08
#परिभाषय CHAN_LOCAL			0x10

/* file descriptor events */
#परिभाषय SSH_CHAN_IO_RFD			0x01
#परिभाषय SSH_CHAN_IO_WFD			0x02
#परिभाषय SSH_CHAN_IO_EFD_R		0x04
#परिभाषय SSH_CHAN_IO_EFD_W		0x08
#परिभाषय SSH_CHAN_IO_EFD			(SSH_CHAN_IO_EFD_R|SSH_CHAN_IO_EFD_W)
#परिभाषय SSH_CHAN_IO_SOCK_R		0x10
#परिभाषय SSH_CHAN_IO_SOCK_W		0x20
#परिभाषय SSH_CHAN_IO_SOCK		(SSH_CHAN_IO_SOCK_R|SSH_CHAN_IO_SOCK_W)

/* Read buffer size */
#परिभाषय CHAN_RBUF	(16*1024)

/* Maximum size for direct reads to buffers */
#परिभाषय CHANNEL_MAX_READ	CHAN_SES_PACKET_DEFAULT

/* Maximum channel input buffer size */
#परिभाषय CHAN_निवेशः_MAX	(16*1024*1024)

/* Hard limit on number of channels */
#परिभाषय CHANNELS_MAX_CHANNELS	(16*1024)

/* check whether 'efd' is still in use */
#परिभाषय CHANNEL_EFD_निवेशः_सक्रिय(c) \
	(c->extended_usage == CHAN_EXTENDED_READ && \
	(c->efd != -1 || \
	sshbuf_len(c->extended) > 0))
#परिभाषय CHANNEL_EFD_OUTPUT_सक्रिय(c) \
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
शून्य	 channel_समुच्चयः_fds(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क,
	    पूर्णाङ्क, पूर्णाङ्क, u_int);
शून्य	 channel_समुच्चयः_tty(संरचना ssh *, Channel *);
शून्य	 channel_free(संरचना ssh *, Channel *);
शून्य	 channel_free_all(संरचना ssh *);
शून्य	 channel_stop_listening(संरचना ssh *);
शून्य	 channel_force_close(संरचना ssh *, Channel *, पूर्णाङ्क);
शून्य	 channel_समुच्चयः_xtype(संरचना ssh *, पूर्णाङ्क, ध्रुव वर्ण *);

शून्य	 channel_send_open(संरचना ssh *, पूर्णाङ्क);
शून्य	 channel_request_start(संरचना ssh *, पूर्णाङ्क, ध्रुव वर्ण *, पूर्णाङ्क);
शून्य	 channel_पञ्जिकाकोशः_cleanup(संरचना ssh *, पूर्णाङ्क,
	    channel_callback_fn *, पूर्णाङ्क);
शून्य	 channel_पञ्जिकाकोशः_open_confirm(संरचना ssh *, पूर्णाङ्क,
	    channel_open_fn *, शून्य *);
शून्य	 channel_पञ्जिकाकोशः_filter(संरचना ssh *, पूर्णाङ्क, channel_infilter_fn *,
	    channel_outfilter_fn *, channel_filter_cleanup_fn *, शून्य *);
शून्य	 channel_पञ्जिकाकोशः_स्थितिः_confirm(संरचना ssh *, पूर्णाङ्क,
	    channel_confirm_cb *, channel_confirm_abandon_cb *, शून्य *);
शून्य	 channel_cancel_cleanup(संरचना ssh *, पूर्णाङ्क);
पूर्णाङ्क	 channel_close_fd(संरचना ssh *, Channel *, पूर्णाङ्क *);
शून्य	 channel_send_गवाक्षः_changes(संरचना ssh *);
पूर्णाङ्क	 channel_has_bulk(संरचना ssh *);
शून्य	 channel_समुच्चयः_tcp_keepalives(संरचना ssh *, पूर्णाङ्क);

/* channel inactivity timeouts */
शून्य channel_सङ्कलय_timeout(संरचना ssh *, ध्रुव वर्ण *, द्विगुण);
शून्य channel_clear_timeouts(संरचना ssh *);

/* mux proxy support */

पूर्णाङ्क	 channel_proxy_downstream(संरचना ssh *, Channel *mc);
पूर्णाङ्क	 channel_proxy_upstream(Channel *, पूर्णाङ्क, uint32_t, संरचना ssh *);

/* protocol handler */

पूर्णाङ्क	 channel_निवेशः_दत्त(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 channel_निवेशः_extended_दत्त(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 channel_निवेशः_ieof(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 channel_निवेशः_oclose(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 channel_निवेशः_open_confirmation(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 channel_निवेशः_open_failure(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 channel_निवेशः_गवाक्षः_adjust(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 channel_निवेशः_स्थितिः_confirm(पूर्णाङ्क, uint32_t, संरचना ssh *);

/* file descriptor handling (read/write) */
संरचना pollfd;
संरचना timespec;

शून्य	 channel_prepare_poll(संरचना ssh *, संरचना pollfd **,
	    u_int *, u_int *, u_int, संरचना timespec *);
शून्य	 channel_after_poll(संरचना ssh *, संरचना pollfd *, u_int);
पूर्णाङ्क	 channel_output_poll(संरचना ssh *);

पूर्णाङ्क      channel_not_very_much_buffered_दत्त(संरचना ssh *);
शून्य     channel_close_all(संरचना ssh *);
पूर्णाङ्क      channel_still_open(संरचना ssh *);
पूर्णाङ्क	 channel_tty_open(संरचना ssh *);
ध्रुव वर्ण *channel_format_extended_usage(ध्रुव Channel *);
वर्ण	*channel_open_सन्देशः(संरचना ssh *);
शून्य	 channel_report_open(संरचना ssh *, पूर्णाङ्क);
पूर्णाङ्क	 channel_find_open(संरचना ssh *);

/* tcp forwarding */
संरचना Forward;
संरचना ForwardOptions;
शून्य	 channel_समुच्चयः_af(संरचना ssh *, पूर्णाङ्क af);
शून्य     channel_permit_all(संरचना ssh *, पूर्णाङ्क);
शून्य	 channel_सङ्कलय_permission(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क, वर्ण *, पूर्णाङ्क);
शून्य	 channel_clear_permission(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क);
शून्य	 channel_disable_admin(संरचना ssh *, पूर्णाङ्क);
शून्य	 channel_update_permission(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क);
Channel	*channel_connect_गन्तव्यम्_पत्तनम्(संरचना ssh *, ध्रुव वर्ण *, u_short,
	    वर्ण *, वर्ण *, पूर्णाङ्क *, ध्रुव वर्ण **);
Channel *channel_connect_गन्तव्यम्_मार्गः(संरचना ssh *, ध्रुव वर्ण *, वर्ण *, वर्ण *);
Channel	*channel_connect_stdio_fwd(संरचना ssh *, ध्रुव वर्ण*,
	    पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क);
Channel	*channel_connect_by_listen_स्थानाङ्कः(संरचना ssh *, ध्रुव वर्ण *,
	    u_short, वर्ण *, वर्ण *);
Channel	*channel_connect_by_listen_मार्गः(संरचना ssh *, ध्रुव वर्ण *,
	    वर्ण *, वर्ण *);
पूर्णाङ्क	 channel_request_remote_forwarding(संरचना ssh *, संरचना Forward *);
पूर्णाङ्क	 channel_सज्जता_local_fwd_listener(संरचना ssh *, संरचना Forward *,
	    संरचना ForwardOptions *);
पूर्णाङ्क	 channel_request_rforward_cancel(संरचना ssh *, संरचना Forward *);
पूर्णाङ्क	 channel_सज्जता_remote_fwd_listener(संरचना ssh *, संरचना Forward *,
	    पूर्णाङ्क *, संरचना ForwardOptions *);
पूर्णाङ्क	 channel_cancel_rport_listener(संरचना ssh *, संरचना Forward *);
पूर्णाङ्क	 channel_cancel_lport_listener(संरचना ssh *, संरचना Forward *,
	    पूर्णाङ्क, संरचना ForwardOptions *);
पूर्णाङ्क	 permitopen_पत्तनम्(ध्रुव वर्ण *);

/* x11 forwarding */

शून्य	 channel_समुच्चयः_x11_refuse_time(संरचना ssh *, द्विगुण);
पूर्णाङ्क	 x11_connect_display(संरचना ssh *);
पूर्णाङ्क	 x11_create_display_inet(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, u_int *, पूर्णाङ्क **);
शून्य	 x11_request_forwarding_with_spoofing(संरचना ssh *, पूर्णाङ्क,
	    ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क);
पूर्णाङ्क      x11_channel_प्रयुक्तम्_recently(संरचना ssh *ssh);

/* channel close */

पूर्णाङ्क	 chan_is_dead(संरचना ssh *, Channel *, पूर्णाङ्क);
शून्य	 chan_mark_dead(संरचना ssh *, Channel *);

/* agent forwarding */
शून्य	 client_channel_request_agent_forwarding(संरचना ssh *, पूर्णाङ्क);

/* channel events */

शून्य	 chan_rcvd_oclose(संरचना ssh *, Channel *);
शून्य	 chan_rcvd_eow(संरचना ssh *, Channel *);
शून्य	 chan_read_failed(संरचना ssh *, Channel *);
शून्य	 chan_ibuf_रिक्तानि(संरचना ssh *, Channel *);
शून्य	 chan_rcvd_ieof(संरचना ssh *, Channel *);
शून्य	 chan_write_failed(संरचना ssh *, Channel *);
शून्य	 chan_obuf_रिक्तानि(संरचना ssh *, Channel *);

#यदि_अन्तः
