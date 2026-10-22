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

#اگر_غیر_تعریف_شدہ CHANNEL_H
#تعریف_کرو CHANNEL_H

/* Definitions for channel types. */
#تعریف_کرو SSH_CHANNEL_X11_LISTENER	1	/* Listening for inet X11 conn. */
#تعریف_کرو SSH_CHANNEL_پورٹ_LISTENER	2	/* Listening on a port. */
#تعریف_کرو SSH_CHANNEL_OPENING		3	/* waiting for confirmation */
#تعریف_کرو SSH_CHANNEL_OPEN		4	/* normal open two-way channel */
#تعریف_کرو SSH_CHANNEL_CLOSED		5	/* waiting for close confirmation */
#تعریف_کرو SSH_CHANNEL_AUTH_SOCKET		6	/* authentication socket */
#تعریف_کرو SSH_CHANNEL_X11_OPEN		7	/* reading first X11 packet */
#تعریف_کرو SSH_CHANNEL_LARVAL		10	/* larval session */
#تعریف_کرو SSH_CHANNEL_RPORT_LISTENER	11	/* Listening to a R-style port  */
#تعریف_کرو SSH_CHANNEL_CONNECTING		12
#تعریف_کرو SSH_CHANNEL_DYNAMIC		13
#تعریف_کرو SSH_CHANNEL_ZOMBIE		14	/* Almost dead. */
#تعریف_کرو SSH_CHANNEL_MUX_LISTENER	15	/* Listener for mux conn. */
#تعریف_کرو SSH_CHANNEL_MUX_CLIENT		16	/* Conn. to mux client */
#تعریف_کرو SSH_CHANNEL_ABANDONED		17	/* Abandoned session, eg mux */
#تعریف_کرو SSH_CHANNEL_UNIX_LISTENER	18	/* Listening on a domain socket. */
#تعریف_کرو SSH_CHANNEL_RUNIX_LISTENER	19	/* Listening to a R-style domain socket. */
#تعریف_کرو SSH_CHANNEL_MUX_PROXY		20	/* proxy channel for mux-client */
#تعریف_کرو SSH_CHANNEL_RDYNAMIC_OPEN	21	/* reverse SOCKS, parsing request */
#تعریف_کرو SSH_CHANNEL_RDYNAMIC_اختتام	22	/* reverse SOCKS, finishing connect */
#تعریف_کرو SSH_CHANNEL_MAX_TYPE		23

#تعریف_کرو CHANNEL_CANCEL_پورٹ_STATIC	-1

/* nonblocking flags for channel_new */
#تعریف_کرو CHANNEL_NONBLOCK_LEAVE	0 /* don't modify non-blocking state */
#تعریف_کرو CHANNEL_NONBLOCK_سیٹ	1 /* set non-blocking state */
#تعریف_کرو CHANNEL_NONBLOCK_STDIO	2 /* set non-blocking and restore on close */

/* c->restore_block mask flags */
#تعریف_کرو CHANNEL_RESTORE_RFD	0x01
#تعریف_کرو CHANNEL_RESTORE_WFD	0x02
#تعریف_کرو CHANNEL_RESTORE_EFD	0x04

/* TCP forwarding */
#تعریف_کرو FORWARD_DENY		0
#تعریف_کرو FORWARD_REMOTE		(1)
#تعریف_کرو FORWARD_LOCAL		(1<<1)
#تعریف_کرو FORWARD_ALLOW		(FORWARD_REMOTE|FORWARD_LOCAL)

#تعریف_کرو FORWARD_ADM		0x100
#تعریف_کرو FORWARD_USER		0x101

/* default pattern-lists used to classify channel types as bulk */
#تعریف_کرو CHANNEL_BULK_TTY	""
#تعریف_کرو CHANNEL_BULK_NOTTY	"direct-*,forwarded-*,dynamic-*," \
				"tun-*,x11-*,session*,stdio-forward"

ساخت ssh;
ساخت Channel;
قسمتعریف ساخت Channel Channel;
ساخت channel_connect;

قسمتعریف خالی channel_open_fn(ساخت ssh *, صحیح, صحیح, خالی *);
قسمتعریف خالی channel_callback_fn(ساخت ssh *, صحیح, صحیح, خالی *);
قسمتعریف صحیح channel_infilter_fn(ساخت ssh *, ساخت Channel *, حرف *, صحیح);
قسمتعریف خالی channel_filter_cleanup_fn(ساخت ssh *, صحیح, خالی *);
قسمتعریف u_char *channel_outfilter_fn(ساخت ssh *, ساخت Channel *,
    u_char **, سائز_t *);

/* Channel success/failure callbacks */
قسمتعریف خالی channel_confirm_cb(ساخت ssh *, صحیح, ساخت Channel *, خالی *);
قسمتعریف خالی channel_confirm_abandon_cb(ساخت ssh *, ساخت Channel *, خالی *);
ساخت channel_confirm {
	TAILQ_ENTRY(channel_confirm) اندراج_2;
	channel_confirm_cb *cb;
	channel_confirm_abandon_cb *abandon_cb;
	خالی *ctx;
};
TAILQ_HEAD(channel_confirms, channel_confirm);

/* Callbacks for mux channels back into client-specific code */
قسمتعریف صحیح mux_callback_fn(ساخت ssh *, ساخت Channel *);

/*
 * NB. channel IDs on the wire and in c->remote_id are uint32, but local
 * channel IDs (e.g. c->self) only ever use the int32 subset of this range,
 * because we use local channel ID -1 for housekeeping. Remote channels have
 * a dedicated "have_remote_id" flag to indicate their validity.
 */

ساخت Channel {
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
	uint32_t ctl_بچہ_id;	/* child session for mux controllers */
	صحیح	have_ctl_بچہ_id;/* non-zero if ctl_child_id is valid */
	صحیح     remote_has_tty;	/* remote side has a tty */
	صحیح     isatty;		/* rfd is a tty */
#اگر_تعریف_شدہ _AIX
	صحیح     wfd_isatty;	/* wfd is a tty */
#اگر_ختم
	صحیح	client_tty;	/* (client) TTY has been requested */
	صحیح     force_drain;	/* force close on iEOF */
	دوہرا	notbefore;	/* Pause IO until deadline (time_t) */
	صحیح     delayed;	/* post-IO handlers for newly created
				 * channels are delayed until the first call
				 * to a matching pre-IO handler.
				 * this way post-IO handlers are not
				 * accidentally called if a FD gets reused */
	صحیح	restore_بلاک;	/* fd mask to restore blocking status */
	صحیح	restore_flags[3];/* flags to restore */
	ساخت sshbuf *داخلہ;	/* data read from socket, to be sent over
				 * encrypted connection */
	ساخت sshbuf *output;	/* data received over encrypted connection for
				 * send on socket */
	ساخت sshbuf *extended;

	حرف    *راستہ;
		/* path for unix domain sockets, or host name for forwards */
	صحیح     listening_پورٹ;	/* port being listened for forwards */
	حرف   *listening_addr;	/* addr being listened for forwards */
	صحیح     host_پورٹ;	/* remote port to connect for forwards */
	حرف   *remote_name;	/* remote hostname */

	u_int	remote_کھڑکی;
	u_int	remote_maxpacket;
	u_int	local_کھڑکی;
	u_int	local_کھڑکی_exceeded;
	u_int	local_کھڑکی_max;
	u_int	local_consumed;
	u_int	local_maxpacket;
	صحیح     extended_usage;
	صحیح	agent_new;	/* For agent listeners, use RFC 9987 requests */
	صحیح	single_connection;

	حرف   *ctype;		/* const type - NB. not freed on channel_free */
	حرف   *xctype;		/* extended type */
	صحیح	bulk;		/* channel is non-interactive */

	/* callback */
	channel_open_fn		*open_confirm;
	خالی			*open_confirm_ctx;
	channel_callback_fn	*detach_user;
	صحیح			detach_close;
	ساخت channel_confirms	حالت_confirms;

	/* filter */
	channel_infilter_fn	*داخلہ_filter;
	channel_outfilter_fn	*output_filter;
	خالی			*filter_ctx;
	channel_filter_cleanup_fn *filter_cleanup;

	/* keep boundaries */
	صحیح			datagram;

	/* non-blocking connect */
	ساخت channel_connect	*connect_ctx;

	/* multiplexing protocol hook, called for each packet received */
	mux_callback_fn		*mux_rcb;
	خالی			*mux_ctx;
	صحیح			mux_pause;
	صحیح			mux_downstream_id;

	/* Inactivity timeouts */

	/* Last traffic seen for OPEN channels */
	دوہرا			lastused;
	/* Inactivity timeout deadline in seconds (0 = no timeout) */
	دوہرا			inactive_deadline;
};

#تعریف_کرو CHAN_EXTENDED_IGNORE		0
#تعریف_کرو CHAN_EXTENDED_READ		1
#تعریف_کرو CHAN_EXTENDED_WRITE		2

/* default window/packet sizes for tcp/x11-fwd-channel */
#تعریف_کرو CHAN_SES_PACKET_DEFAULT	(32*1024)
#تعریف_کرو CHAN_SES_کھڑکی_DEFAULT	(64*CHAN_SES_PACKET_DEFAULT)
#تعریف_کرو CHAN_TCP_PACKET_DEFAULT	(32*1024)
#تعریف_کرو CHAN_TCP_کھڑکی_DEFAULT	(64*CHAN_TCP_PACKET_DEFAULT)
#تعریف_کرو CHAN_X11_PACKET_DEFAULT	(16*1024)
#تعریف_کرو CHAN_X11_کھڑکی_DEFAULT	(4*CHAN_X11_PACKET_DEFAULT)

/* possible input states */
#تعریف_کرو CHAN_داخلہ_OPEN			0
#تعریف_کرو CHAN_داخلہ_WAIT_DRAIN		1
#تعریف_کرو CHAN_داخلہ_WAIT_OCLOSE		2
#تعریف_کرو CHAN_داخلہ_CLOSED		3

/* possible output states */
#تعریف_کرو CHAN_OUTPUT_OPEN		0
#تعریف_کرو CHAN_OUTPUT_WAIT_DRAIN		1
#تعریف_کرو CHAN_OUTPUT_WAIT_IEOF		2
#تعریف_کرو CHAN_OUTPUT_CLOSED		3

#تعریف_کرو CHAN_CLOSE_بھیجا			0x01
#تعریف_کرو CHAN_CLOSE_RCVD			0x02
#تعریف_کرو CHAN_EOF_بھیجا			0x04
#تعریف_کرو CHAN_EOF_RCVD			0x08
#تعریف_کرو CHAN_LOCAL			0x10

/* file descriptor events */
#تعریف_کرو SSH_CHAN_IO_RFD			0x01
#تعریف_کرو SSH_CHAN_IO_WFD			0x02
#تعریف_کرو SSH_CHAN_IO_EFD_R		0x04
#تعریف_کرو SSH_CHAN_IO_EFD_W		0x08
#تعریف_کرو SSH_CHAN_IO_EFD			(SSH_CHAN_IO_EFD_R|SSH_CHAN_IO_EFD_W)
#تعریف_کرو SSH_CHAN_IO_SOCK_R		0x10
#تعریف_کرو SSH_CHAN_IO_SOCK_W		0x20
#تعریف_کرو SSH_CHAN_IO_SOCK		(SSH_CHAN_IO_SOCK_R|SSH_CHAN_IO_SOCK_W)

/* Read buffer size */
#تعریف_کرو CHAN_RBUF	(16*1024)

/* Maximum size for direct reads to buffers */
#تعریف_کرو CHANNEL_MAX_READ	CHAN_SES_PACKET_DEFAULT

/* Maximum channel input buffer size */
#تعریف_کرو CHAN_داخلہ_MAX	(16*1024*1024)

/* Hard limit on number of channels */
#تعریف_کرو CHANNELS_MAX_CHANNELS	(16*1024)

/* check whether 'efd' is still in use */
#تعریف_کرو CHANNEL_EFD_داخلہ_فعال(c) \
	(c->extended_usage == CHAN_EXTENDED_READ && \
	(c->efd != -1 || \
	sshbuf_len(c->extended) > 0))
#تعریف_کرو CHANNEL_EFD_OUTPUT_فعال(c) \
	(c->extended_usage == CHAN_EXTENDED_WRITE && \
	c->efd != -1 && (!(c->flags & (CHAN_EOF_RCVD|CHAN_CLOSE_RCVD)) || \
	sshbuf_len(c->extended) > 0))

/* Add/remove channel management structures to/from SSH transport instance */
خالی channel_init_channels(ساخت ssh *ssh);
خالی channel_free_channels(ساخت ssh *ssh);

/* channel management */

Channel	*channel_by_id(ساخت ssh *, صحیح);
Channel	*channel_by_remote_id(ساخت ssh *, u_int);
Channel	*channel_lookup(ساخت ssh *, صحیح);
Channel *channel_new(ساخت ssh *, حرف *, صحیح, صحیح, صحیح, صحیح,
	    u_int, u_int, صحیح, ثابت حرف *, صحیح);
خالی	 channel_سیٹ_fds(ساخت ssh *, صحیح, صحیح, صحیح, صحیح, صحیح,
	    صحیح, صحیح, u_int);
خالی	 channel_سیٹ_tty(ساخت ssh *, Channel *);
خالی	 channel_free(ساخت ssh *, Channel *);
خالی	 channel_free_all(ساخت ssh *);
خالی	 channel_stop_listening(ساخت ssh *);
خالی	 channel_force_close(ساخت ssh *, Channel *, صحیح);
خالی	 channel_سیٹ_xtype(ساخت ssh *, صحیح, ثابت حرف *);

خالی	 channel_send_open(ساخت ssh *, صحیح);
خالی	 channel_request_آغاز(ساخت ssh *, صحیح, ثابت حرف *, صحیح);
خالی	 channel_رجسٹر_cleanup(ساخت ssh *, صحیح,
	    channel_callback_fn *, صحیح);
خالی	 channel_رجسٹر_open_confirm(ساخت ssh *, صحیح,
	    channel_open_fn *, خالی *);
خالی	 channel_رجسٹر_filter(ساخت ssh *, صحیح, channel_infilter_fn *,
	    channel_outfilter_fn *, channel_filter_cleanup_fn *, خالی *);
خالی	 channel_رجسٹر_حالت_confirm(ساخت ssh *, صحیح,
	    channel_confirm_cb *, channel_confirm_abandon_cb *, خالی *);
خالی	 channel_cancel_cleanup(ساخت ssh *, صحیح);
صحیح	 channel_close_fd(ساخت ssh *, Channel *, صحیح *);
خالی	 channel_send_کھڑکی_changes(ساخت ssh *);
صحیح	 channel_has_bulk(ساخت ssh *);
خالی	 channel_سیٹ_tcp_keepalives(ساخت ssh *, صحیح);

/* channel inactivity timeouts */
خالی channel_جوڑو_timeout(ساخت ssh *, ثابت حرف *, دوہرا);
خالی channel_clear_timeouts(ساخت ssh *);

/* mux proxy support */

صحیح	 channel_proxy_downstream(ساخت ssh *, Channel *mc);
صحیح	 channel_proxy_upstream(Channel *, صحیح, uint32_t, ساخت ssh *);

/* protocol handler */

صحیح	 channel_داخلہ_ڈیٹا(صحیح, uint32_t, ساخت ssh *);
صحیح	 channel_داخلہ_extended_ڈیٹا(صحیح, uint32_t, ساخت ssh *);
صحیح	 channel_داخلہ_ieof(صحیح, uint32_t, ساخت ssh *);
صحیح	 channel_داخلہ_oclose(صحیح, uint32_t, ساخت ssh *);
صحیح	 channel_داخلہ_open_confirmation(صحیح, uint32_t, ساخت ssh *);
صحیح	 channel_داخلہ_open_failure(صحیح, uint32_t, ساخت ssh *);
صحیح	 channel_داخلہ_کھڑکی_adjust(صحیح, uint32_t, ساخت ssh *);
صحیح	 channel_داخلہ_حالت_confirm(صحیح, uint32_t, ساخت ssh *);

/* file descriptor handling (read/write) */
ساخت pollfd;
ساخت timespec;

خالی	 channel_prepare_poll(ساخت ssh *, ساخت pollfd **,
	    u_int *, u_int *, u_int, ساخت timespec *);
خالی	 channel_after_poll(ساخت ssh *, ساخت pollfd *, u_int);
صحیح	 channel_output_poll(ساخت ssh *);

صحیح      channel_not_very_much_buffered_ڈیٹا(ساخت ssh *);
خالی     channel_close_all(ساخت ssh *);
صحیح      channel_still_open(ساخت ssh *);
صحیح	 channel_tty_open(ساخت ssh *);
ثابت حرف *channel_format_extended_usage(ثابت Channel *);
حرف	*channel_open_پیغام(ساخت ssh *);
خالی	 channel_report_open(ساخت ssh *, صحیح);
صحیح	 channel_ڈھونڈو_open(ساخت ssh *);

/* tcp forwarding */
ساخت Forward;
ساخت ForwardOptions;
خالی	 channel_سیٹ_af(ساخت ssh *, صحیح af);
خالی     channel_permit_all(ساخت ssh *, صحیح);
خالی	 channel_جوڑو_permission(ساخت ssh *, صحیح, صحیح, حرف *, صحیح);
خالی	 channel_clear_permission(ساخت ssh *, صحیح, صحیح);
خالی	 channel_disable_admin(ساخت ssh *, صحیح);
خالی	 channel_update_permission(ساخت ssh *, صحیح, صحیح);
Channel	*channel_connect_مقصد_پورٹ(ساخت ssh *, ثابت حرف *, u_short,
	    حرف *, حرف *, صحیح *, ثابت حرف **);
Channel *channel_connect_مقصد_راستہ(ساخت ssh *, ثابت حرف *, حرف *, حرف *);
Channel	*channel_connect_stdio_fwd(ساخت ssh *, ثابت حرف*,
	    صحیح, صحیح, صحیح, صحیح);
Channel	*channel_connect_by_listen_پتہ(ساخت ssh *, ثابت حرف *,
	    u_short, حرف *, حرف *);
Channel	*channel_connect_by_listen_راستہ(ساخت ssh *, ثابت حرف *,
	    حرف *, حرف *);
صحیح	 channel_request_remote_forwarding(ساخت ssh *, ساخت Forward *);
صحیح	 channel_تیاری_local_fwd_listener(ساخت ssh *, ساخت Forward *,
	    ساخت ForwardOptions *);
صحیح	 channel_request_rforward_cancel(ساخت ssh *, ساخت Forward *);
صحیح	 channel_تیاری_remote_fwd_listener(ساخت ssh *, ساخت Forward *,
	    صحیح *, ساخت ForwardOptions *);
صحیح	 channel_cancel_rport_listener(ساخت ssh *, ساخت Forward *);
صحیح	 channel_cancel_lport_listener(ساخت ssh *, ساخت Forward *,
	    صحیح, ساخت ForwardOptions *);
صحیح	 permitopen_پورٹ(ثابت حرف *);

/* x11 forwarding */

خالی	 channel_سیٹ_x11_refuse_وقت(ساخت ssh *, دوہرا);
صحیح	 x11_connect_display(ساخت ssh *);
صحیح	 x11_create_display_inet(ساخت ssh *, صحیح, صحیح, صحیح, u_int *, صحیح **);
خالی	 x11_request_forwarding_with_spoofing(ساخت ssh *, صحیح,
	    ثابت حرف *, ثابت حرف *, ثابت حرف *, صحیح);
صحیح      x11_channel_مستعمل_recently(ساخت ssh *ssh);

/* channel close */

صحیح	 chan_is_dead(ساخت ssh *, Channel *, صحیح);
خالی	 chan_mark_dead(ساخت ssh *, Channel *);

/* agent forwarding */
خالی	 client_channel_request_agent_forwarding(ساخت ssh *, صحیح);

/* channel events */

خالی	 chan_rcvd_oclose(ساخت ssh *, Channel *);
خالی	 chan_rcvd_eow(ساخت ssh *, Channel *);
خالی	 chan_read_failed(ساخت ssh *, Channel *);
خالی	 chan_ibuf_خالی_خانے(ساخت ssh *, Channel *);
خالی	 chan_rcvd_ieof(ساخت ssh *, Channel *);
خالی	 chan_write_failed(ساخت ssh *, Channel *);
خالی	 chan_obuf_خالی_خانے(ساخت ssh *, Channel *);

#اگر_ختم
