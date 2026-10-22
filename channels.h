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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ CHANNEL_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNEL_H

/* Definitions for channel types. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_X11_LISTENER	1	/* Listening for inet X11 conn. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_ਪੋਰਟ_LISTENER	2	/* Listening on a port. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_OPENING		3	/* waiting for confirmation */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_OPEN		4	/* normal open two-way channel */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_CLOSED		5	/* waiting for close confirmation */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_AUTH_SOCKET		6	/* authentication socket */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_X11_OPEN		7	/* reading first X11 packet */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_LARVAL		10	/* larval session */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_RPORT_LISTENER	11	/* Listening to a R-style port  */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_CONNECTING		12
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_DYNAMIC		13
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_ZOMBIE		14	/* Almost dead. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_MUX_LISTENER	15	/* Listener for mux conn. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_MUX_CLIENT		16	/* Conn. to mux client */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_ABANDONED		17	/* Abandoned session, eg mux */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_UNIX_LISTENER	18	/* Listening on a domain socket. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_RUNIX_LISTENER	19	/* Listening to a R-style domain socket. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_MUX_PROXY		20	/* proxy channel for mux-client */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_RDYNAMIC_OPEN	21	/* reverse SOCKS, parsing request */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_RDYNAMIC_ਅੰਤ	22	/* reverse SOCKS, finishing connect */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHANNEL_MAX_TYPE		23

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNEL_CANCEL_ਪੋਰਟ_STATIC	-1

/* nonblocking flags for channel_new */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNEL_NONBLOCK_LEAVE	0 /* don't modify non-blocking state */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNEL_NONBLOCK_ਸੈੱਟ	1 /* set non-blocking state */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNEL_NONBLOCK_STDIO	2 /* set non-blocking and restore on close */

/* c->restore_block mask flags */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNEL_RESTORE_RFD	0x01
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNEL_RESTORE_WFD	0x02
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNEL_RESTORE_EFD	0x04

/* TCP forwarding */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FORWARD_DENY		0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FORWARD_REMOTE		(1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FORWARD_LOCAL		(1<<1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FORWARD_ALLOW		(FORWARD_REMOTE|FORWARD_LOCAL)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FORWARD_ADM		0x100
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FORWARD_USER		0x101

/* default pattern-lists used to classify channel types as bulk */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNEL_BULK_TTY	""
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNEL_BULK_NOTTY	"direct-*,forwarded-*,dynamic-*," \
				"tun-*,x11-*,session*,stdio-forward"

ਬਣਤਰ ssh;
ਬਣਤਰ Channel;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ Channel Channel;
ਬਣਤਰ channel_connect;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ channel_open_fn(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ, ਖਾਲੀ *);
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ channel_callback_fn(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ, ਖਾਲੀ *);
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ channel_infilter_fn(ਬਣਤਰ ssh *, ਬਣਤਰ Channel *, ਅੱਖਰ *, ਪੂਰਨ);
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ channel_filter_cleanup_fn(ਬਣਤਰ ssh *, ਪੂਰਨ, ਖਾਲੀ *);
ਕਿਸਮਪਰਿਭਾਸ਼ਾ u_char *channel_outfilter_fn(ਬਣਤਰ ssh *, ਬਣਤਰ Channel *,
    u_char **, ਮਾਪ_t *);

/* Channel success/failure callbacks */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ channel_confirm_cb(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ Channel *, ਖਾਲੀ *);
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ channel_confirm_abandon_cb(ਬਣਤਰ ssh *, ਬਣਤਰ Channel *, ਖਾਲੀ *);
ਬਣਤਰ channel_confirm {
	TAILQ_ENTRY(channel_confirm) ਇੰਦਰਾਜ;
	channel_confirm_cb *cb;
	channel_confirm_abandon_cb *abandon_cb;
	ਖਾਲੀ *ctx;
};
TAILQ_HEAD(channel_confirms, channel_confirm);

/* Callbacks for mux channels back into client-specific code */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ mux_callback_fn(ਬਣਤਰ ssh *, ਬਣਤਰ Channel *);

/*
 * NB. channel IDs on the wire and in c->remote_id are uint32, but local
 * channel IDs (e.g. c->self) only ever use the int32 subset of this range,
 * because we use local channel ID -1 for housekeeping. Remote channels have
 * a dedicated "have_remote_id" flag to indicate their validity.
 */

ਬਣਤਰ Channel {
	ਪੂਰਨ     type;		/* channel type/state */

	ਪੂਰਨ     self;		/* my own channel identifier */
	uint32_t remote_id;	/* channel identifier for remote peer */
	ਪੂਰਨ	have_remote_id;	/* non-zero if remote_id is valid */

	u_int   istate;		/* input from channel (state of receive half) */
	u_int   ostate;		/* output to channel  (state of transmit half) */
	ਪੂਰਨ     flags;		/* close sent/rcvd */
	ਪੂਰਨ     rfd;		/* read fd */
	ਪੂਰਨ     wfd;		/* write fd */
	ਪੂਰਨ     efd;		/* extended fd */
	ਪੂਰਨ     sock;		/* sock fd */
	u_int	io_want;	/* bitmask of SSH_CHAN_IO_* */
	u_int	io_ready;	/* bitmask of SSH_CHAN_IO_* */
	ਪੂਰਨ	pfds[4];	/* pollfd entries for rfd/wfd/efd/sock */
	ਪੂਰਨ     ctl_chan;	/* control channel (multiplexed connections) */
	uint32_t ctl_ਬੱਚਾ_id;	/* child session for mux controllers */
	ਪੂਰਨ	have_ctl_ਬੱਚਾ_id;/* non-zero if ctl_child_id is valid */
	ਪੂਰਨ     remote_has_tty;	/* remote side has a tty */
	ਪੂਰਨ     isatty;		/* rfd is a tty */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ _AIX
	ਪੂਰਨ     wfd_isatty;	/* wfd is a tty */
#ਜੇ_ਅੰਤ
	ਪੂਰਨ	client_tty;	/* (client) TTY has been requested */
	ਪੂਰਨ     force_drain;	/* force close on iEOF */
	ਦੁੱਗਣਾ	notbefore;	/* Pause IO until deadline (time_t) */
	ਪੂਰਨ     delayed;	/* post-IO handlers for newly created
				 * channels are delayed until the first call
				 * to a matching pre-IO handler.
				 * this way post-IO handlers are not
				 * accidentally called if a FD gets reused */
	ਪੂਰਨ	restore_ਖੰਡ;	/* fd mask to restore blocking status */
	ਪੂਰਨ	restore_flags[3];/* flags to restore */
	ਬਣਤਰ sshbuf *ਨਿਵੇਸ਼;	/* data read from socket, to be sent over
				 * encrypted connection */
	ਬਣਤਰ sshbuf *output;	/* data received over encrypted connection for
				 * send on socket */
	ਬਣਤਰ sshbuf *extended;

	ਅੱਖਰ    *ਰਸਤਾ;
		/* path for unix domain sockets, or host name for forwards */
	ਪੂਰਨ     listening_ਪੋਰਟ;	/* port being listened for forwards */
	ਅੱਖਰ   *listening_addr;	/* addr being listened for forwards */
	ਪੂਰਨ     host_ਪੋਰਟ;	/* remote port to connect for forwards */
	ਅੱਖਰ   *remote_name;	/* remote hostname */

	u_int	remote_ਖਿੜਕੀ;
	u_int	remote_maxpacket;
	u_int	local_ਖਿੜਕੀ;
	u_int	local_ਖਿੜਕੀ_exceeded;
	u_int	local_ਖਿੜਕੀ_max;
	u_int	local_consumed;
	u_int	local_maxpacket;
	ਪੂਰਨ     extended_usage;
	ਪੂਰਨ	agent_new;	/* For agent listeners, use RFC 9987 requests */
	ਪੂਰਨ	single_connection;

	ਅੱਖਰ   *ctype;		/* const type - NB. not freed on channel_free */
	ਅੱਖਰ   *xctype;		/* extended type */
	ਪੂਰਨ	bulk;		/* channel is non-interactive */

	/* callback */
	channel_open_fn		*open_confirm;
	ਖਾਲੀ			*open_confirm_ctx;
	channel_callback_fn	*detach_user;
	ਪੂਰਨ			detach_close;
	ਬਣਤਰ channel_confirms	ਸਥਿਤੀ_confirms;

	/* filter */
	channel_infilter_fn	*ਨਿਵੇਸ਼_filter;
	channel_outfilter_fn	*output_filter;
	ਖਾਲੀ			*filter_ctx;
	channel_filter_cleanup_fn *filter_cleanup;

	/* keep boundaries */
	ਪੂਰਨ			datagram;

	/* non-blocking connect */
	ਬਣਤਰ channel_connect	*connect_ctx;

	/* multiplexing protocol hook, called for each packet received */
	mux_callback_fn		*mux_rcb;
	ਖਾਲੀ			*mux_ctx;
	ਪੂਰਨ			mux_pause;
	ਪੂਰਨ			mux_downstream_id;

	/* Inactivity timeouts */

	/* Last traffic seen for OPEN channels */
	ਦੁੱਗਣਾ			lastused;
	/* Inactivity timeout deadline in seconds (0 = no timeout) */
	ਦੁੱਗਣਾ			inactive_deadline;
};

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_EXTENDED_IGNORE		0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_EXTENDED_READ		1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_EXTENDED_WRITE		2

/* default window/packet sizes for tcp/x11-fwd-channel */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_SES_PACKET_DEFAULT	(32*1024)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_SES_ਖਿੜਕੀ_DEFAULT	(64*CHAN_SES_PACKET_DEFAULT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_TCP_PACKET_DEFAULT	(32*1024)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_TCP_ਖਿੜਕੀ_DEFAULT	(64*CHAN_TCP_PACKET_DEFAULT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_X11_PACKET_DEFAULT	(16*1024)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_X11_ਖਿੜਕੀ_DEFAULT	(4*CHAN_X11_PACKET_DEFAULT)

/* possible input states */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_ਨਿਵੇਸ਼_OPEN			0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_ਨਿਵੇਸ਼_WAIT_DRAIN		1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_ਨਿਵੇਸ਼_WAIT_OCLOSE		2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_ਨਿਵੇਸ਼_CLOSED		3

/* possible output states */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_OUTPUT_OPEN		0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_OUTPUT_WAIT_DRAIN		1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_OUTPUT_WAIT_IEOF		2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_OUTPUT_CLOSED		3

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_CLOSE_ਭੇਜਿਆ			0x01
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_CLOSE_RCVD			0x02
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_EOF_ਭੇਜਿਆ			0x04
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_EOF_RCVD			0x08
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_LOCAL			0x10

/* file descriptor events */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHAN_IO_RFD			0x01
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHAN_IO_WFD			0x02
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHAN_IO_EFD_R		0x04
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHAN_IO_EFD_W		0x08
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHAN_IO_EFD			(SSH_CHAN_IO_EFD_R|SSH_CHAN_IO_EFD_W)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHAN_IO_SOCK_R		0x10
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHAN_IO_SOCK_W		0x20
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CHAN_IO_SOCK		(SSH_CHAN_IO_SOCK_R|SSH_CHAN_IO_SOCK_W)

/* Read buffer size */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_RBUF	(16*1024)

/* Maximum size for direct reads to buffers */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNEL_MAX_READ	CHAN_SES_PACKET_DEFAULT

/* Maximum channel input buffer size */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHAN_ਨਿਵੇਸ਼_MAX	(16*1024*1024)

/* Hard limit on number of channels */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNELS_MAX_CHANNELS	(16*1024)

/* check whether 'efd' is still in use */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNEL_EFD_ਨਿਵੇਸ਼_ਸਰਗਰਮ(c) \
	(c->extended_usage == CHAN_EXTENDED_READ && \
	(c->efd != -1 || \
	sshbuf_len(c->extended) > 0))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHANNEL_EFD_OUTPUT_ਸਰਗਰਮ(c) \
	(c->extended_usage == CHAN_EXTENDED_WRITE && \
	c->efd != -1 && (!(c->flags & (CHAN_EOF_RCVD|CHAN_CLOSE_RCVD)) || \
	sshbuf_len(c->extended) > 0))

/* Add/remove channel management structures to/from SSH transport instance */
ਖਾਲੀ channel_init_channels(ਬਣਤਰ ssh *ssh);
ਖਾਲੀ channel_free_channels(ਬਣਤਰ ssh *ssh);

/* channel management */

Channel	*channel_by_id(ਬਣਤਰ ssh *, ਪੂਰਨ);
Channel	*channel_by_remote_id(ਬਣਤਰ ssh *, u_int);
Channel	*channel_lookup(ਬਣਤਰ ssh *, ਪੂਰਨ);
Channel *channel_new(ਬਣਤਰ ssh *, ਅੱਖਰ *, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ,
	    u_int, u_int, ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);
ਖਾਲੀ	 channel_ਸੈੱਟ_fds(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ,
	    ਪੂਰਨ, ਪੂਰਨ, u_int);
ਖਾਲੀ	 channel_ਸੈੱਟ_tty(ਬਣਤਰ ssh *, Channel *);
ਖਾਲੀ	 channel_free(ਬਣਤਰ ssh *, Channel *);
ਖਾਲੀ	 channel_free_all(ਬਣਤਰ ssh *);
ਖਾਲੀ	 channel_stop_listening(ਬਣਤਰ ssh *);
ਖਾਲੀ	 channel_force_close(ਬਣਤਰ ssh *, Channel *, ਪੂਰਨ);
ਖਾਲੀ	 channel_ਸੈੱਟ_xtype(ਬਣਤਰ ssh *, ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *);

ਖਾਲੀ	 channel_send_open(ਬਣਤਰ ssh *, ਪੂਰਨ);
ਖਾਲੀ	 channel_request_ਸ਼ੁਰੂ(ਬਣਤਰ ssh *, ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);
ਖਾਲੀ	 channel_ਰਜਿਸਟਰ_cleanup(ਬਣਤਰ ssh *, ਪੂਰਨ,
	    channel_callback_fn *, ਪੂਰਨ);
ਖਾਲੀ	 channel_ਰਜਿਸਟਰ_open_confirm(ਬਣਤਰ ssh *, ਪੂਰਨ,
	    channel_open_fn *, ਖਾਲੀ *);
ਖਾਲੀ	 channel_ਰਜਿਸਟਰ_filter(ਬਣਤਰ ssh *, ਪੂਰਨ, channel_infilter_fn *,
	    channel_outfilter_fn *, channel_filter_cleanup_fn *, ਖਾਲੀ *);
ਖਾਲੀ	 channel_ਰਜਿਸਟਰ_ਸਥਿਤੀ_confirm(ਬਣਤਰ ssh *, ਪੂਰਨ,
	    channel_confirm_cb *, channel_confirm_abandon_cb *, ਖਾਲੀ *);
ਖਾਲੀ	 channel_cancel_cleanup(ਬਣਤਰ ssh *, ਪੂਰਨ);
ਪੂਰਨ	 channel_close_fd(ਬਣਤਰ ssh *, Channel *, ਪੂਰਨ *);
ਖਾਲੀ	 channel_send_ਖਿੜਕੀ_changes(ਬਣਤਰ ssh *);
ਪੂਰਨ	 channel_has_bulk(ਬਣਤਰ ssh *);
ਖਾਲੀ	 channel_ਸੈੱਟ_tcp_keepalives(ਬਣਤਰ ssh *, ਪੂਰਨ);

/* channel inactivity timeouts */
ਖਾਲੀ channel_ਜੋੜੋ_timeout(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *, ਦੁੱਗਣਾ);
ਖਾਲੀ channel_clear_timeouts(ਬਣਤਰ ssh *);

/* mux proxy support */

ਪੂਰਨ	 channel_proxy_downstream(ਬਣਤਰ ssh *, Channel *mc);
ਪੂਰਨ	 channel_proxy_upstream(Channel *, ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);

/* protocol handler */

ਪੂਰਨ	 channel_ਨਿਵੇਸ਼_ਅੰਕੜੇ(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਪੂਰਨ	 channel_ਨਿਵੇਸ਼_extended_ਅੰਕੜੇ(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਪੂਰਨ	 channel_ਨਿਵੇਸ਼_ieof(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਪੂਰਨ	 channel_ਨਿਵੇਸ਼_oclose(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਪੂਰਨ	 channel_ਨਿਵੇਸ਼_open_confirmation(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਪੂਰਨ	 channel_ਨਿਵੇਸ਼_open_failure(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਪੂਰਨ	 channel_ਨਿਵੇਸ਼_ਖਿੜਕੀ_adjust(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਪੂਰਨ	 channel_ਨਿਵੇਸ਼_ਸਥਿਤੀ_confirm(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);

/* file descriptor handling (read/write) */
ਬਣਤਰ pollfd;
ਬਣਤਰ timespec;

ਖਾਲੀ	 channel_prepare_poll(ਬਣਤਰ ssh *, ਬਣਤਰ pollfd **,
	    u_int *, u_int *, u_int, ਬਣਤਰ timespec *);
ਖਾਲੀ	 channel_after_poll(ਬਣਤਰ ssh *, ਬਣਤਰ pollfd *, u_int);
ਪੂਰਨ	 channel_output_poll(ਬਣਤਰ ssh *);

ਪੂਰਨ      channel_not_very_much_buffered_ਅੰਕੜੇ(ਬਣਤਰ ssh *);
ਖਾਲੀ     channel_close_all(ਬਣਤਰ ssh *);
ਪੂਰਨ      channel_still_open(ਬਣਤਰ ssh *);
ਪੂਰਨ	 channel_tty_open(ਬਣਤਰ ssh *);
ਅਚਲ ਅੱਖਰ *channel_format_extended_usage(ਅਚਲ Channel *);
ਅੱਖਰ	*channel_open_ਸੁਨੇਹਾ(ਬਣਤਰ ssh *);
ਖਾਲੀ	 channel_report_open(ਬਣਤਰ ssh *, ਪੂਰਨ);
ਪੂਰਨ	 channel_ਲੱਭੋ_open(ਬਣਤਰ ssh *);

/* tcp forwarding */
ਬਣਤਰ Forward;
ਬਣਤਰ ForwardOptions;
ਖਾਲੀ	 channel_ਸੈੱਟ_af(ਬਣਤਰ ssh *, ਪੂਰਨ af);
ਖਾਲੀ     channel_permit_all(ਬਣਤਰ ssh *, ਪੂਰਨ);
ਖਾਲੀ	 channel_ਜੋੜੋ_permission(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ, ਅੱਖਰ *, ਪੂਰਨ);
ਖਾਲੀ	 channel_clear_permission(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ);
ਖਾਲੀ	 channel_disable_admin(ਬਣਤਰ ssh *, ਪੂਰਨ);
ਖਾਲੀ	 channel_update_permission(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ);
Channel	*channel_connect_ਮੰਜ਼ਿਲ_ਪੋਰਟ(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *, u_short,
	    ਅੱਖਰ *, ਅੱਖਰ *, ਪੂਰਨ *, ਅਚਲ ਅੱਖਰ **);
Channel *channel_connect_ਮੰਜ਼ਿਲ_ਰਸਤਾ(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ *, ਅੱਖਰ *);
Channel	*channel_connect_stdio_fwd(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ*,
	    ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ);
Channel	*channel_connect_by_listen_ਪਤਾ(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *,
	    u_short, ਅੱਖਰ *, ਅੱਖਰ *);
Channel	*channel_connect_by_listen_ਰਸਤਾ(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *,
	    ਅੱਖਰ *, ਅੱਖਰ *);
ਪੂਰਨ	 channel_request_remote_forwarding(ਬਣਤਰ ssh *, ਬਣਤਰ Forward *);
ਪੂਰਨ	 channel_ਤਿਆਰੀ_local_fwd_listener(ਬਣਤਰ ssh *, ਬਣਤਰ Forward *,
	    ਬਣਤਰ ForwardOptions *);
ਪੂਰਨ	 channel_request_rforward_cancel(ਬਣਤਰ ssh *, ਬਣਤਰ Forward *);
ਪੂਰਨ	 channel_ਤਿਆਰੀ_remote_fwd_listener(ਬਣਤਰ ssh *, ਬਣਤਰ Forward *,
	    ਪੂਰਨ *, ਬਣਤਰ ForwardOptions *);
ਪੂਰਨ	 channel_cancel_rport_listener(ਬਣਤਰ ssh *, ਬਣਤਰ Forward *);
ਪੂਰਨ	 channel_cancel_lport_listener(ਬਣਤਰ ssh *, ਬਣਤਰ Forward *,
	    ਪੂਰਨ, ਬਣਤਰ ForwardOptions *);
ਪੂਰਨ	 permitopen_ਪੋਰਟ(ਅਚਲ ਅੱਖਰ *);

/* x11 forwarding */

ਖਾਲੀ	 channel_ਸੈੱਟ_x11_refuse_ਸਮਾਂ(ਬਣਤਰ ssh *, ਦੁੱਗਣਾ);
ਪੂਰਨ	 x11_connect_display(ਬਣਤਰ ssh *);
ਪੂਰਨ	 x11_create_display_inet(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, u_int *, ਪੂਰਨ **);
ਖਾਲੀ	 x11_request_forwarding_with_spoofing(ਬਣਤਰ ssh *, ਪੂਰਨ,
	    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);
ਪੂਰਨ      x11_channel_ਵਰਤਿਆ_recently(ਬਣਤਰ ssh *ssh);

/* channel close */

ਪੂਰਨ	 chan_is_dead(ਬਣਤਰ ssh *, Channel *, ਪੂਰਨ);
ਖਾਲੀ	 chan_mark_dead(ਬਣਤਰ ssh *, Channel *);

/* agent forwarding */
ਖਾਲੀ	 client_channel_request_agent_forwarding(ਬਣਤਰ ssh *, ਪੂਰਨ);

/* channel events */

ਖਾਲੀ	 chan_rcvd_oclose(ਬਣਤਰ ssh *, Channel *);
ਖਾਲੀ	 chan_rcvd_eow(ਬਣਤਰ ssh *, Channel *);
ਖਾਲੀ	 chan_read_failed(ਬਣਤਰ ssh *, Channel *);
ਖਾਲੀ	 chan_ibuf_ਖਾਲੀ_ਥਾਵਾਂ(ਬਣਤਰ ssh *, Channel *);
ਖਾਲੀ	 chan_rcvd_ieof(ਬਣਤਰ ssh *, Channel *);
ਖਾਲੀ	 chan_write_failed(ਬਣਤਰ ssh *, Channel *);
ਖਾਲੀ	 chan_obuf_ਖਾਲੀ_ਥਾਵਾਂ(ਬਣਤਰ ssh *, Channel *);

#ਜੇ_ਅੰਤ
