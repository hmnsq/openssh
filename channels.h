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

#నిర్వచితం_కాకపోతే CHANNEL_H
#నిర్వచించు CHANNEL_H

/* Definitions for channel types. */
#నిర్వచించు SSH_CHANNEL_X11_LISTENER	1	/* Listening for inet X11 conn. */
#నిర్వచించు SSH_CHANNEL_పోర్టు_LISTENER	2	/* Listening on a port. */
#నిర్వచించు SSH_CHANNEL_OPENING		3	/* waiting for confirmation */
#నిర్వచించు SSH_CHANNEL_OPEN		4	/* normal open two-way channel */
#నిర్వచించు SSH_CHANNEL_CLOSED		5	/* waiting for close confirmation */
#నిర్వచించు SSH_CHANNEL_AUTH_SOCKET		6	/* authentication socket */
#నిర్వచించు SSH_CHANNEL_X11_OPEN		7	/* reading first X11 packet */
#నిర్వచించు SSH_CHANNEL_LARVAL		10	/* larval session */
#నిర్వచించు SSH_CHANNEL_RPORT_LISTENER	11	/* Listening to a R-style port  */
#నిర్వచించు SSH_CHANNEL_CONNECTING		12
#నిర్వచించు SSH_CHANNEL_DYNAMIC		13
#నిర్వచించు SSH_CHANNEL_ZOMBIE		14	/* Almost dead. */
#నిర్వచించు SSH_CHANNEL_MUX_LISTENER	15	/* Listener for mux conn. */
#నిర్వచించు SSH_CHANNEL_MUX_CLIENT		16	/* Conn. to mux client */
#నిర్వచించు SSH_CHANNEL_ABANDONED		17	/* Abandoned session, eg mux */
#నిర్వచించు SSH_CHANNEL_UNIX_LISTENER	18	/* Listening on a domain socket. */
#నిర్వచించు SSH_CHANNEL_RUNIX_LISTENER	19	/* Listening to a R-style domain socket. */
#నిర్వచించు SSH_CHANNEL_MUX_PROXY		20	/* proxy channel for mux-client */
#నిర్వచించు SSH_CHANNEL_RDYNAMIC_OPEN	21	/* reverse SOCKS, parsing request */
#నిర్వచించు SSH_CHANNEL_RDYNAMIC_ముగింపు	22	/* reverse SOCKS, finishing connect */
#నిర్వచించు SSH_CHANNEL_MAX_TYPE		23

#నిర్వచించు CHANNEL_CANCEL_పోర్టు_STATIC	-1

/* nonblocking flags for channel_new */
#నిర్వచించు CHANNEL_NONBLOCK_LEAVE	0 /* don't modify non-blocking state */
#నిర్వచించు CHANNEL_NONBLOCK_సమితి	1 /* set non-blocking state */
#నిర్వచించు CHANNEL_NONBLOCK_STDIO	2 /* set non-blocking and restore on close */

/* c->restore_block mask flags */
#నిర్వచించు CHANNEL_RESTORE_RFD	0x01
#నిర్వచించు CHANNEL_RESTORE_WFD	0x02
#నిర్వచించు CHANNEL_RESTORE_EFD	0x04

/* TCP forwarding */
#నిర్వచించు FORWARD_DENY		0
#నిర్వచించు FORWARD_REMOTE		(1)
#నిర్వచించు FORWARD_LOCAL		(1<<1)
#నిర్వచించు FORWARD_ALLOW		(FORWARD_REMOTE|FORWARD_LOCAL)

#నిర్వచించు FORWARD_ADM		0x100
#నిర్వచించు FORWARD_USER		0x101

/* default pattern-lists used to classify channel types as bulk */
#నిర్వచించు CHANNEL_BULK_TTY	""
#నిర్వచించు CHANNEL_BULK_NOTTY	"direct-*,forwarded-*,dynamic-*," \
				"tun-*,x11-*,session*,stdio-forward"

నిర్మాణం ssh;
నిర్మాణం Channel;
రకనిర్వచనం నిర్మాణం Channel Channel;
నిర్మాణం channel_connect;

రకనిర్వచనం శూన్య channel_open_fn(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం, శూన్య *);
రకనిర్వచనం శూన్య channel_callback_fn(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం, శూన్య *);
రకనిర్వచనం పూర్ణాంకం channel_infilter_fn(నిర్మాణం ssh *, నిర్మాణం Channel *, అక్షరం *, పూర్ణాంకం);
రకనిర్వచనం శూన్య channel_filter_cleanup_fn(నిర్మాణం ssh *, పూర్ణాంకం, శూన్య *);
రకనిర్వచనం u_char *channel_outfilter_fn(నిర్మాణం ssh *, నిర్మాణం Channel *,
    u_char **, కొలత_t *);

/* Channel success/failure callbacks */
రకనిర్వచనం శూన్య channel_confirm_cb(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం Channel *, శూన్య *);
రకనిర్వచనం శూన్య channel_confirm_abandon_cb(నిర్మాణం ssh *, నిర్మాణం Channel *, శూన్య *);
నిర్మాణం channel_confirm {
	TAILQ_ENTRY(channel_confirm) నమోదు_2;
	channel_confirm_cb *cb;
	channel_confirm_abandon_cb *abandon_cb;
	శూన్య *ctx;
};
TAILQ_HEAD(channel_confirms, channel_confirm);

/* Callbacks for mux channels back into client-specific code */
రకనిర్వచనం పూర్ణాంకం mux_callback_fn(నిర్మాణం ssh *, నిర్మాణం Channel *);

/*
 * NB. channel IDs on the wire and in c->remote_id are uint32, but local
 * channel IDs (e.g. c->self) only ever use the int32 subset of this range,
 * because we use local channel ID -1 for housekeeping. Remote channels have
 * a dedicated "have_remote_id" flag to indicate their validity.
 */

నిర్మాణం Channel {
	పూర్ణాంకం     type;		/* channel type/state */

	పూర్ణాంకం     self;		/* my own channel identifier */
	uint32_t remote_id;	/* channel identifier for remote peer */
	పూర్ణాంకం	have_remote_id;	/* non-zero if remote_id is valid */

	u_int   istate;		/* input from channel (state of receive half) */
	u_int   ostate;		/* output to channel  (state of transmit half) */
	పూర్ణాంకం     flags;		/* close sent/rcvd */
	పూర్ణాంకం     rfd;		/* read fd */
	పూర్ణాంకం     wfd;		/* write fd */
	పూర్ణాంకం     efd;		/* extended fd */
	పూర్ణాంకం     sock;		/* sock fd */
	u_int	io_want;	/* bitmask of SSH_CHAN_IO_* */
	u_int	io_ready;	/* bitmask of SSH_CHAN_IO_* */
	పూర్ణాంకం	pfds[4];	/* pollfd entries for rfd/wfd/efd/sock */
	పూర్ణాంకం     ctl_chan;	/* control channel (multiplexed connections) */
	uint32_t ctl_బిడ్డ_id;	/* child session for mux controllers */
	పూర్ణాంకం	have_ctl_బిడ్డ_id;/* non-zero if ctl_child_id is valid */
	పూర్ణాంకం     remote_has_tty;	/* remote side has a tty */
	పూర్ణాంకం     isatty;		/* rfd is a tty */
#నిర్వచితమైతే _AIX
	పూర్ణాంకం     wfd_isatty;	/* wfd is a tty */
#అయితే_ముగింపు
	పూర్ణాంకం	client_tty;	/* (client) TTY has been requested */
	పూర్ణాంకం     force_drain;	/* force close on iEOF */
	ద్విగుణ	notbefore;	/* Pause IO until deadline (time_t) */
	పూర్ణాంకం     delayed;	/* post-IO handlers for newly created
				 * channels are delayed until the first call
				 * to a matching pre-IO handler.
				 * this way post-IO handlers are not
				 * accidentally called if a FD gets reused */
	పూర్ణాంకం	restore_ఖండం;	/* fd mask to restore blocking status */
	పూర్ణాంకం	restore_flags[3];/* flags to restore */
	నిర్మాణం sshbuf *ఆదానం;	/* data read from socket, to be sent over
				 * encrypted connection */
	నిర్మాణం sshbuf *output;	/* data received over encrypted connection for
				 * send on socket */
	నిర్మాణం sshbuf *extended;

	అక్షరం    *మార్గం;
		/* path for unix domain sockets, or host name for forwards */
	పూర్ణాంకం     listening_పోర్టు;	/* port being listened for forwards */
	అక్షరం   *listening_addr;	/* addr being listened for forwards */
	పూర్ణాంకం     host_పోర్టు;	/* remote port to connect for forwards */
	అక్షరం   *remote_name;	/* remote hostname */

	u_int	remote_కిటికీ;
	u_int	remote_maxpacket;
	u_int	local_కిటికీ;
	u_int	local_కిటికీ_exceeded;
	u_int	local_కిటికీ_max;
	u_int	local_consumed;
	u_int	local_maxpacket;
	పూర్ణాంకం     extended_usage;
	పూర్ణాంకం	agent_new;	/* For agent listeners, use RFC 9987 requests */
	పూర్ణాంకం	single_connection;

	అక్షరం   *ctype;		/* const type - NB. not freed on channel_free */
	అక్షరం   *xctype;		/* extended type */
	పూర్ణాంకం	bulk;		/* channel is non-interactive */

	/* callback */
	channel_open_fn		*open_confirm;
	శూన్య			*open_confirm_ctx;
	channel_callback_fn	*detach_user;
	పూర్ణాంకం			detach_close;
	నిర్మాణం channel_confirms	స్థితి_confirms;

	/* filter */
	channel_infilter_fn	*ఆదానం_filter;
	channel_outfilter_fn	*output_filter;
	శూన్య			*filter_ctx;
	channel_filter_cleanup_fn *filter_cleanup;

	/* keep boundaries */
	పూర్ణాంకం			datagram;

	/* non-blocking connect */
	నిర్మాణం channel_connect	*connect_ctx;

	/* multiplexing protocol hook, called for each packet received */
	mux_callback_fn		*mux_rcb;
	శూన్య			*mux_ctx;
	పూర్ణాంకం			mux_pause;
	పూర్ణాంకం			mux_downstream_id;

	/* Inactivity timeouts */

	/* Last traffic seen for OPEN channels */
	ద్విగుణ			lastused;
	/* Inactivity timeout deadline in seconds (0 = no timeout) */
	ద్విగుణ			inactive_deadline;
};

#నిర్వచించు CHAN_EXTENDED_IGNORE		0
#నిర్వచించు CHAN_EXTENDED_READ		1
#నిర్వచించు CHAN_EXTENDED_WRITE		2

/* default window/packet sizes for tcp/x11-fwd-channel */
#నిర్వచించు CHAN_SES_PACKET_DEFAULT	(32*1024)
#నిర్వచించు CHAN_SES_కిటికీ_DEFAULT	(64*CHAN_SES_PACKET_DEFAULT)
#నిర్వచించు CHAN_TCP_PACKET_DEFAULT	(32*1024)
#నిర్వచించు CHAN_TCP_కిటికీ_DEFAULT	(64*CHAN_TCP_PACKET_DEFAULT)
#నిర్వచించు CHAN_X11_PACKET_DEFAULT	(16*1024)
#నిర్వచించు CHAN_X11_కిటికీ_DEFAULT	(4*CHAN_X11_PACKET_DEFAULT)

/* possible input states */
#నిర్వచించు CHAN_ఆదానం_OPEN			0
#నిర్వచించు CHAN_ఆదానం_WAIT_DRAIN		1
#నిర్వచించు CHAN_ఆదానం_WAIT_OCLOSE		2
#నిర్వచించు CHAN_ఆదానం_CLOSED		3

/* possible output states */
#నిర్వచించు CHAN_OUTPUT_OPEN		0
#నిర్వచించు CHAN_OUTPUT_WAIT_DRAIN		1
#నిర్వచించు CHAN_OUTPUT_WAIT_IEOF		2
#నిర్వచించు CHAN_OUTPUT_CLOSED		3

#నిర్వచించు CHAN_CLOSE_పంపిన			0x01
#నిర్వచించు CHAN_CLOSE_RCVD			0x02
#నిర్వచించు CHAN_EOF_పంపిన			0x04
#నిర్వచించు CHAN_EOF_RCVD			0x08
#నిర్వచించు CHAN_LOCAL			0x10

/* file descriptor events */
#నిర్వచించు SSH_CHAN_IO_RFD			0x01
#నిర్వచించు SSH_CHAN_IO_WFD			0x02
#నిర్వచించు SSH_CHAN_IO_EFD_R		0x04
#నిర్వచించు SSH_CHAN_IO_EFD_W		0x08
#నిర్వచించు SSH_CHAN_IO_EFD			(SSH_CHAN_IO_EFD_R|SSH_CHAN_IO_EFD_W)
#నిర్వచించు SSH_CHAN_IO_SOCK_R		0x10
#నిర్వచించు SSH_CHAN_IO_SOCK_W		0x20
#నిర్వచించు SSH_CHAN_IO_SOCK		(SSH_CHAN_IO_SOCK_R|SSH_CHAN_IO_SOCK_W)

/* Read buffer size */
#నిర్వచించు CHAN_RBUF	(16*1024)

/* Maximum size for direct reads to buffers */
#నిర్వచించు CHANNEL_MAX_READ	CHAN_SES_PACKET_DEFAULT

/* Maximum channel input buffer size */
#నిర్వచించు CHAN_ఆదానం_MAX	(16*1024*1024)

/* Hard limit on number of channels */
#నిర్వచించు CHANNELS_MAX_CHANNELS	(16*1024)

/* check whether 'efd' is still in use */
#నిర్వచించు CHANNEL_EFD_ఆదానం_చురుకైన(c) \
	(c->extended_usage == CHAN_EXTENDED_READ && \
	(c->efd != -1 || \
	sshbuf_len(c->extended) > 0))
#నిర్వచించు CHANNEL_EFD_OUTPUT_చురుకైన(c) \
	(c->extended_usage == CHAN_EXTENDED_WRITE && \
	c->efd != -1 && (!(c->flags & (CHAN_EOF_RCVD|CHAN_CLOSE_RCVD)) || \
	sshbuf_len(c->extended) > 0))

/* Add/remove channel management structures to/from SSH transport instance */
శూన్య channel_init_channels(నిర్మాణం ssh *ssh);
శూన్య channel_free_channels(నిర్మాణం ssh *ssh);

/* channel management */

Channel	*channel_by_id(నిర్మాణం ssh *, పూర్ణాంకం);
Channel	*channel_by_remote_id(నిర్మాణం ssh *, u_int);
Channel	*channel_lookup(నిర్మాణం ssh *, పూర్ణాంకం);
Channel *channel_new(నిర్మాణం ssh *, అక్షరం *, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం,
	    u_int, u_int, పూర్ణాంకం, స్థిరరాశి అక్షరం *, పూర్ణాంకం);
శూన్య	 channel_సమితి_fds(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం,
	    పూర్ణాంకం, పూర్ణాంకం, u_int);
శూన్య	 channel_సమితి_tty(నిర్మాణం ssh *, Channel *);
శూన్య	 channel_free(నిర్మాణం ssh *, Channel *);
శూన్య	 channel_free_all(నిర్మాణం ssh *);
శూన్య	 channel_stop_listening(నిర్మాణం ssh *);
శూన్య	 channel_force_close(నిర్మాణం ssh *, Channel *, పూర్ణాంకం);
శూన్య	 channel_సమితి_xtype(నిర్మాణం ssh *, పూర్ణాంకం, స్థిరరాశి అక్షరం *);

శూన్య	 channel_send_open(నిర్మాణం ssh *, పూర్ణాంకం);
శూన్య	 channel_request_ప్రారంభం(నిర్మాణం ssh *, పూర్ణాంకం, స్థిరరాశి అక్షరం *, పూర్ణాంకం);
శూన్య	 channel_రిజిస్టరు_cleanup(నిర్మాణం ssh *, పూర్ణాంకం,
	    channel_callback_fn *, పూర్ణాంకం);
శూన్య	 channel_రిజిస్టరు_open_confirm(నిర్మాణం ssh *, పూర్ణాంకం,
	    channel_open_fn *, శూన్య *);
శూన్య	 channel_రిజిస్టరు_filter(నిర్మాణం ssh *, పూర్ణాంకం, channel_infilter_fn *,
	    channel_outfilter_fn *, channel_filter_cleanup_fn *, శూన్య *);
శూన్య	 channel_రిజిస్టరు_స్థితి_confirm(నిర్మాణం ssh *, పూర్ణాంకం,
	    channel_confirm_cb *, channel_confirm_abandon_cb *, శూన్య *);
శూన్య	 channel_cancel_cleanup(నిర్మాణం ssh *, పూర్ణాంకం);
పూర్ణాంకం	 channel_close_fd(నిర్మాణం ssh *, Channel *, పూర్ణాంకం *);
శూన్య	 channel_send_కిటికీ_changes(నిర్మాణం ssh *);
పూర్ణాంకం	 channel_has_bulk(నిర్మాణం ssh *);
శూన్య	 channel_సమితి_tcp_keepalives(నిర్మాణం ssh *, పూర్ణాంకం);

/* channel inactivity timeouts */
శూన్య channel_కూడు_timeout(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *, ద్విగుణ);
శూన్య channel_clear_timeouts(నిర్మాణం ssh *);

/* mux proxy support */

పూర్ణాంకం	 channel_proxy_downstream(నిర్మాణం ssh *, Channel *mc);
పూర్ణాంకం	 channel_proxy_upstream(Channel *, పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);

/* protocol handler */

పూర్ణాంకం	 channel_ఆదానం_దత్తాంశం(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
పూర్ణాంకం	 channel_ఆదానం_extended_దత్తాంశం(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
పూర్ణాంకం	 channel_ఆదానం_ieof(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
పూర్ణాంకం	 channel_ఆదానం_oclose(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
పూర్ణాంకం	 channel_ఆదానం_open_confirmation(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
పూర్ణాంకం	 channel_ఆదానం_open_failure(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
పూర్ణాంకం	 channel_ఆదానం_కిటికీ_adjust(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
పూర్ణాంకం	 channel_ఆదానం_స్థితి_confirm(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);

/* file descriptor handling (read/write) */
నిర్మాణం pollfd;
నిర్మాణం timespec;

శూన్య	 channel_prepare_poll(నిర్మాణం ssh *, నిర్మాణం pollfd **,
	    u_int *, u_int *, u_int, నిర్మాణం timespec *);
శూన్య	 channel_after_poll(నిర్మాణం ssh *, నిర్మాణం pollfd *, u_int);
పూర్ణాంకం	 channel_output_poll(నిర్మాణం ssh *);

పూర్ణాంకం      channel_not_very_much_buffered_దత్తాంశం(నిర్మాణం ssh *);
శూన్య     channel_close_all(నిర్మాణం ssh *);
పూర్ణాంకం      channel_still_open(నిర్మాణం ssh *);
పూర్ణాంకం	 channel_tty_open(నిర్మాణం ssh *);
స్థిరరాశి అక్షరం *channel_format_extended_usage(స్థిరరాశి Channel *);
అక్షరం	*channel_open_సందేశం(నిర్మాణం ssh *);
శూన్య	 channel_report_open(నిర్మాణం ssh *, పూర్ణాంకం);
పూర్ణాంకం	 channel_కనుగొను_open(నిర్మాణం ssh *);

/* tcp forwarding */
నిర్మాణం Forward;
నిర్మాణం ForwardOptions;
శూన్య	 channel_సమితి_af(నిర్మాణం ssh *, పూర్ణాంకం af);
శూన్య     channel_permit_all(నిర్మాణం ssh *, పూర్ణాంకం);
శూన్య	 channel_కూడు_permission(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం, అక్షరం *, పూర్ణాంకం);
శూన్య	 channel_clear_permission(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం);
శూన్య	 channel_disable_admin(నిర్మాణం ssh *, పూర్ణాంకం);
శూన్య	 channel_update_permission(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం);
Channel	*channel_connect_గమ్యం_పోర్టు(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *, u_short,
	    అక్షరం *, అక్షరం *, పూర్ణాంకం *, స్థిరరాశి అక్షరం **);
Channel *channel_connect_గమ్యం_మార్గం(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *, అక్షరం *, అక్షరం *);
Channel	*channel_connect_stdio_fwd(నిర్మాణం ssh *, స్థిరరాశి అక్షరం*,
	    పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం);
Channel	*channel_connect_by_listen_చిరునామా(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *,
	    u_short, అక్షరం *, అక్షరం *);
Channel	*channel_connect_by_listen_మార్గం(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *,
	    అక్షరం *, అక్షరం *);
పూర్ణాంకం	 channel_request_remote_forwarding(నిర్మాణం ssh *, నిర్మాణం Forward *);
పూర్ణాంకం	 channel_అమరిక_local_fwd_listener(నిర్మాణం ssh *, నిర్మాణం Forward *,
	    నిర్మాణం ForwardOptions *);
పూర్ణాంకం	 channel_request_rforward_cancel(నిర్మాణం ssh *, నిర్మాణం Forward *);
పూర్ణాంకం	 channel_అమరిక_remote_fwd_listener(నిర్మాణం ssh *, నిర్మాణం Forward *,
	    పూర్ణాంకం *, నిర్మాణం ForwardOptions *);
పూర్ణాంకం	 channel_cancel_rport_listener(నిర్మాణం ssh *, నిర్మాణం Forward *);
పూర్ణాంకం	 channel_cancel_lport_listener(నిర్మాణం ssh *, నిర్మాణం Forward *,
	    పూర్ణాంకం, నిర్మాణం ForwardOptions *);
పూర్ణాంకం	 permitopen_పోర్టు(స్థిరరాశి అక్షరం *);

/* x11 forwarding */

శూన్య	 channel_సమితి_x11_refuse_సమయం(నిర్మాణం ssh *, ద్విగుణ);
పూర్ణాంకం	 x11_connect_display(నిర్మాణం ssh *);
పూర్ణాంకం	 x11_create_display_inet(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, u_int *, పూర్ణాంకం **);
శూన్య	 x11_request_forwarding_with_spoofing(నిర్మాణం ssh *, పూర్ణాంకం,
	    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం);
పూర్ణాంకం      x11_channel_వాడిన_recently(నిర్మాణం ssh *ssh);

/* channel close */

పూర్ణాంకం	 chan_is_dead(నిర్మాణం ssh *, Channel *, పూర్ణాంకం);
శూన్య	 chan_mark_dead(నిర్మాణం ssh *, Channel *);

/* agent forwarding */
శూన్య	 client_channel_request_agent_forwarding(నిర్మాణం ssh *, పూర్ణాంకం);

/* channel events */

శూన్య	 chan_rcvd_oclose(నిర్మాణం ssh *, Channel *);
శూన్య	 chan_rcvd_eow(నిర్మాణం ssh *, Channel *);
శూన్య	 chan_read_failed(నిర్మాణం ssh *, Channel *);
శూన్య	 chan_ibuf_ఖాళీలు(నిర్మాణం ssh *, Channel *);
శూన్య	 chan_rcvd_ieof(నిర్మాణం ssh *, Channel *);
శూన్య	 chan_write_failed(నిర్మాణం ssh *, Channel *);
శూన్య	 chan_obuf_ఖాళీలు(నిర్మాణం ssh *, Channel *);

#అయితే_ముగింపు
