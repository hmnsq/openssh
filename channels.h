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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ CHANNEL_H
#ವ್ಯಾಖ್ಯಾನಿಸು CHANNEL_H

/* Definitions for channel types. */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_X11_LISTENER	1	/* Listening for inet X11 conn. */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_ಪೋರ್ಟ್_LISTENER	2	/* Listening on a port. */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_OPENING		3	/* waiting for confirmation */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_OPEN		4	/* normal open two-way channel */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_CLOSED		5	/* waiting for close confirmation */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_AUTH_SOCKET		6	/* authentication socket */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_X11_OPEN		7	/* reading first X11 packet */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_LARVAL		10	/* larval session */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_RPORT_LISTENER	11	/* Listening to a R-style port  */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_CONNECTING		12
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_DYNAMIC		13
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_ZOMBIE		14	/* Almost dead. */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_MUX_LISTENER	15	/* Listener for mux conn. */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_MUX_CLIENT		16	/* Conn. to mux client */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_ABANDONED		17	/* Abandoned session, eg mux */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_UNIX_LISTENER	18	/* Listening on a domain socket. */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_RUNIX_LISTENER	19	/* Listening to a R-style domain socket. */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_MUX_PROXY		20	/* proxy channel for mux-client */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_RDYNAMIC_OPEN	21	/* reverse SOCKS, parsing request */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_RDYNAMIC_ಮುಕ್ತಾಯ	22	/* reverse SOCKS, finishing connect */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHANNEL_MAX_TYPE		23

#ವ್ಯಾಖ್ಯಾನಿಸು CHANNEL_CANCEL_ಪೋರ್ಟ್_STATIC	-1

/* nonblocking flags for channel_new */
#ವ್ಯಾಖ್ಯಾನಿಸು CHANNEL_NONBLOCK_LEAVE	0 /* don't modify non-blocking state */
#ವ್ಯಾಖ್ಯಾನಿಸು CHANNEL_NONBLOCK_ಗಣ	1 /* set non-blocking state */
#ವ್ಯಾಖ್ಯಾನಿಸು CHANNEL_NONBLOCK_STDIO	2 /* set non-blocking and restore on close */

/* c->restore_block mask flags */
#ವ್ಯಾಖ್ಯಾನಿಸು CHANNEL_RESTORE_RFD	0x01
#ವ್ಯಾಖ್ಯಾನಿಸು CHANNEL_RESTORE_WFD	0x02
#ವ್ಯಾಖ್ಯಾನಿಸು CHANNEL_RESTORE_EFD	0x04

/* TCP forwarding */
#ವ್ಯಾಖ್ಯಾನಿಸು FORWARD_DENY		0
#ವ್ಯಾಖ್ಯಾನಿಸು FORWARD_REMOTE		(1)
#ವ್ಯಾಖ್ಯಾನಿಸು FORWARD_LOCAL		(1<<1)
#ವ್ಯಾಖ್ಯಾನಿಸು FORWARD_ALLOW		(FORWARD_REMOTE|FORWARD_LOCAL)

#ವ್ಯಾಖ್ಯಾನಿಸು FORWARD_ADM		0x100
#ವ್ಯಾಖ್ಯಾನಿಸು FORWARD_USER		0x101

/* default pattern-lists used to classify channel types as bulk */
#ವ್ಯಾಖ್ಯಾನಿಸು CHANNEL_BULK_TTY	""
#ವ್ಯಾಖ್ಯಾನಿಸು CHANNEL_BULK_NOTTY	"direct-*,forwarded-*,dynamic-*," \
				"tun-*,x11-*,session*,stdio-forward"

ರಚನೆ ssh;
ರಚನೆ Channel;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Channel Channel;
ರಚನೆ channel_connect;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ channel_open_fn(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಶೂನ್ಯ *);
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ channel_callback_fn(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಶೂನ್ಯ *);
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಪೂರ್ಣಾಂಕ channel_infilter_fn(ರಚನೆ ssh *, ರಚನೆ Channel *, ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ channel_filter_cleanup_fn(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಶೂನ್ಯ *);
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ u_char *channel_outfilter_fn(ರಚನೆ ssh *, ರಚನೆ Channel *,
    u_char **, ಗಾತ್ರ_t *);

/* Channel success/failure callbacks */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ channel_confirm_cb(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ Channel *, ಶೂನ್ಯ *);
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ channel_confirm_abandon_cb(ರಚನೆ ssh *, ರಚನೆ Channel *, ಶೂನ್ಯ *);
ರಚನೆ channel_confirm {
	TAILQ_ENTRY(channel_confirm) ನಮೂದು;
	channel_confirm_cb *cb;
	channel_confirm_abandon_cb *abandon_cb;
	ಶೂನ್ಯ *ctx;
};
TAILQ_HEAD(channel_confirms, channel_confirm);

/* Callbacks for mux channels back into client-specific code */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಪೂರ್ಣಾಂಕ mux_callback_fn(ರಚನೆ ssh *, ರಚನೆ Channel *);

/*
 * NB. channel IDs on the wire and in c->remote_id are uint32, but local
 * channel IDs (e.g. c->self) only ever use the int32 subset of this range,
 * because we use local channel ID -1 for housekeeping. Remote channels have
 * a dedicated "have_remote_id" flag to indicate their validity.
 */

ರಚನೆ Channel {
	ಪೂರ್ಣಾಂಕ     type;		/* channel type/state */

	ಪೂರ್ಣಾಂಕ     self;		/* my own channel identifier */
	uint32_t remote_id;	/* channel identifier for remote peer */
	ಪೂರ್ಣಾಂಕ	have_remote_id;	/* non-zero if remote_id is valid */

	u_int   istate;		/* input from channel (state of receive half) */
	u_int   ostate;		/* output to channel  (state of transmit half) */
	ಪೂರ್ಣಾಂಕ     flags;		/* close sent/rcvd */
	ಪೂರ್ಣಾಂಕ     rfd;		/* read fd */
	ಪೂರ್ಣಾಂಕ     wfd;		/* write fd */
	ಪೂರ್ಣಾಂಕ     efd;		/* extended fd */
	ಪೂರ್ಣಾಂಕ     sock;		/* sock fd */
	u_int	io_want;	/* bitmask of SSH_CHAN_IO_* */
	u_int	io_ready;	/* bitmask of SSH_CHAN_IO_* */
	ಪೂರ್ಣಾಂಕ	pfds[4];	/* pollfd entries for rfd/wfd/efd/sock */
	ಪೂರ್ಣಾಂಕ     ctl_chan;	/* control channel (multiplexed connections) */
	uint32_t ctl_ಮಗು_id;	/* child session for mux controllers */
	ಪೂರ್ಣಾಂಕ	have_ctl_ಮಗು_id;/* non-zero if ctl_child_id is valid */
	ಪೂರ್ಣಾಂಕ     remote_has_tty;	/* remote side has a tty */
	ಪೂರ್ಣಾಂಕ     isatty;		/* rfd is a tty */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ _AIX
	ಪೂರ್ಣಾಂಕ     wfd_isatty;	/* wfd is a tty */
#ಆದರೆ_ಅಂತ್ಯ
	ಪೂರ್ಣಾಂಕ	client_tty;	/* (client) TTY has been requested */
	ಪೂರ್ಣಾಂಕ     force_drain;	/* force close on iEOF */
	ದ್ವಿಗುಣ	notbefore;	/* Pause IO until deadline (time_t) */
	ಪೂರ್ಣಾಂಕ     delayed;	/* post-IO handlers for newly created
				 * channels are delayed until the first call
				 * to a matching pre-IO handler.
				 * this way post-IO handlers are not
				 * accidentally called if a FD gets reused */
	ಪೂರ್ಣಾಂಕ	restore_ಖಂಡ;	/* fd mask to restore blocking status */
	ಪೂರ್ಣಾಂಕ	restore_flags[3];/* flags to restore */
	ರಚನೆ sshbuf *ಒಳಹರಿವು;	/* data read from socket, to be sent over
				 * encrypted connection */
	ರಚನೆ sshbuf *output;	/* data received over encrypted connection for
				 * send on socket */
	ರಚನೆ sshbuf *extended;

	ಅಕ್ಷರ    *ಮಾರ್ಗ;
		/* path for unix domain sockets, or host name for forwards */
	ಪೂರ್ಣಾಂಕ     listening_ಪೋರ್ಟ್;	/* port being listened for forwards */
	ಅಕ್ಷರ   *listening_addr;	/* addr being listened for forwards */
	ಪೂರ್ಣಾಂಕ     host_ಪೋರ್ಟ್;	/* remote port to connect for forwards */
	ಅಕ್ಷರ   *remote_name;	/* remote hostname */

	u_int	remote_ಕಿಟಕಿ;
	u_int	remote_maxpacket;
	u_int	local_ಕಿಟಕಿ;
	u_int	local_ಕಿಟಕಿ_exceeded;
	u_int	local_ಕಿಟಕಿ_max;
	u_int	local_consumed;
	u_int	local_maxpacket;
	ಪೂರ್ಣಾಂಕ     extended_usage;
	ಪೂರ್ಣಾಂಕ	agent_new;	/* For agent listeners, use RFC 9987 requests */
	ಪೂರ್ಣಾಂಕ	single_connection;

	ಅಕ್ಷರ   *ctype;		/* const type - NB. not freed on channel_free */
	ಅಕ್ಷರ   *xctype;		/* extended type */
	ಪೂರ್ಣಾಂಕ	bulk;		/* channel is non-interactive */

	/* callback */
	channel_open_fn		*open_confirm;
	ಶೂನ್ಯ			*open_confirm_ctx;
	channel_callback_fn	*detach_user;
	ಪೂರ್ಣಾಂಕ			detach_close;
	ರಚನೆ channel_confirms	ಸ್ಥಿತಿ_confirms;

	/* filter */
	channel_infilter_fn	*ಒಳಹರಿವು_filter;
	channel_outfilter_fn	*output_filter;
	ಶೂನ್ಯ			*filter_ctx;
	channel_filter_cleanup_fn *filter_cleanup;

	/* keep boundaries */
	ಪೂರ್ಣಾಂಕ			datagram;

	/* non-blocking connect */
	ರಚನೆ channel_connect	*connect_ctx;

	/* multiplexing protocol hook, called for each packet received */
	mux_callback_fn		*mux_rcb;
	ಶೂನ್ಯ			*mux_ctx;
	ಪೂರ್ಣಾಂಕ			mux_pause;
	ಪೂರ್ಣಾಂಕ			mux_downstream_id;

	/* Inactivity timeouts */

	/* Last traffic seen for OPEN channels */
	ದ್ವಿಗುಣ			lastused;
	/* Inactivity timeout deadline in seconds (0 = no timeout) */
	ದ್ವಿಗುಣ			inactive_deadline;
};

#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_EXTENDED_IGNORE		0
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_EXTENDED_READ		1
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_EXTENDED_WRITE		2

/* default window/packet sizes for tcp/x11-fwd-channel */
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_SES_PACKET_DEFAULT	(32*1024)
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_SES_ಕಿಟಕಿ_DEFAULT	(64*CHAN_SES_PACKET_DEFAULT)
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_TCP_PACKET_DEFAULT	(32*1024)
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_TCP_ಕಿಟಕಿ_DEFAULT	(64*CHAN_TCP_PACKET_DEFAULT)
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_X11_PACKET_DEFAULT	(16*1024)
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_X11_ಕಿಟಕಿ_DEFAULT	(4*CHAN_X11_PACKET_DEFAULT)

/* possible input states */
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_ಒಳಹರಿವು_OPEN			0
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_ಒಳಹರಿವು_WAIT_DRAIN		1
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_ಒಳಹರಿವು_WAIT_OCLOSE		2
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_ಒಳಹರಿವು_CLOSED		3

/* possible output states */
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_OUTPUT_OPEN		0
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_OUTPUT_WAIT_DRAIN		1
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_OUTPUT_WAIT_IEOF		2
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_OUTPUT_CLOSED		3

#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_CLOSE_ಕಳುಹಿಸಿದ			0x01
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_CLOSE_RCVD			0x02
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_EOF_ಕಳುಹಿಸಿದ			0x04
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_EOF_RCVD			0x08
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_LOCAL			0x10

/* file descriptor events */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHAN_IO_RFD			0x01
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHAN_IO_WFD			0x02
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHAN_IO_EFD_R		0x04
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHAN_IO_EFD_W		0x08
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHAN_IO_EFD			(SSH_CHAN_IO_EFD_R|SSH_CHAN_IO_EFD_W)
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHAN_IO_SOCK_R		0x10
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHAN_IO_SOCK_W		0x20
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CHAN_IO_SOCK		(SSH_CHAN_IO_SOCK_R|SSH_CHAN_IO_SOCK_W)

/* Read buffer size */
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_RBUF	(16*1024)

/* Maximum size for direct reads to buffers */
#ವ್ಯಾಖ್ಯಾನಿಸು CHANNEL_MAX_READ	CHAN_SES_PACKET_DEFAULT

/* Maximum channel input buffer size */
#ವ್ಯಾಖ್ಯಾನಿಸು CHAN_ಒಳಹರಿವು_MAX	(16*1024*1024)

/* Hard limit on number of channels */
#ವ್ಯಾಖ್ಯಾನಿಸು CHANNELS_MAX_CHANNELS	(16*1024)

/* check whether 'efd' is still in use */
#ವ್ಯಾಖ್ಯಾನಿಸು CHANNEL_EFD_ಒಳಹರಿವು_ಸಕ್ರಿಯ(c) \
	(c->extended_usage == CHAN_EXTENDED_READ && \
	(c->efd != -1 || \
	sshbuf_len(c->extended) > 0))
#ವ್ಯಾಖ್ಯಾನಿಸು CHANNEL_EFD_OUTPUT_ಸಕ್ರಿಯ(c) \
	(c->extended_usage == CHAN_EXTENDED_WRITE && \
	c->efd != -1 && (!(c->flags & (CHAN_EOF_RCVD|CHAN_CLOSE_RCVD)) || \
	sshbuf_len(c->extended) > 0))

/* Add/remove channel management structures to/from SSH transport instance */
ಶೂನ್ಯ channel_init_channels(ರಚನೆ ssh *ssh);
ಶೂನ್ಯ channel_free_channels(ರಚನೆ ssh *ssh);

/* channel management */

Channel	*channel_by_id(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);
Channel	*channel_by_remote_id(ರಚನೆ ssh *, u_int);
Channel	*channel_lookup(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);
Channel *channel_new(ರಚನೆ ssh *, ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ,
	    u_int, u_int, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 channel_ಗಣ_fds(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ,
	    ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, u_int);
ಶೂನ್ಯ	 channel_ಗಣ_tty(ರಚನೆ ssh *, Channel *);
ಶೂನ್ಯ	 channel_free(ರಚನೆ ssh *, Channel *);
ಶೂನ್ಯ	 channel_free_all(ರಚನೆ ssh *);
ಶೂನ್ಯ	 channel_stop_listening(ರಚನೆ ssh *);
ಶೂನ್ಯ	 channel_force_close(ರಚನೆ ssh *, Channel *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 channel_ಗಣ_xtype(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಶೂನ್ಯ	 channel_send_open(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 channel_request_ಆರಂಭ(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 channel_ರಿಜಿಸ್ಟರ್_cleanup(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ,
	    channel_callback_fn *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 channel_ರಿಜಿಸ್ಟರ್_open_confirm(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ,
	    channel_open_fn *, ಶೂನ್ಯ *);
ಶೂನ್ಯ	 channel_ರಿಜಿಸ್ಟರ್_filter(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, channel_infilter_fn *,
	    channel_outfilter_fn *, channel_filter_cleanup_fn *, ಶೂನ್ಯ *);
ಶೂನ್ಯ	 channel_ರಿಜಿಸ್ಟರ್_ಸ್ಥಿತಿ_confirm(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ,
	    channel_confirm_cb *, channel_confirm_abandon_cb *, ಶೂನ್ಯ *);
ಶೂನ್ಯ	 channel_cancel_cleanup(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 channel_close_fd(ರಚನೆ ssh *, Channel *, ಪೂರ್ಣಾಂಕ *);
ಶೂನ್ಯ	 channel_send_ಕಿಟಕಿ_changes(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 channel_has_bulk(ರಚನೆ ssh *);
ಶೂನ್ಯ	 channel_ಗಣ_tcp_keepalives(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);

/* channel inactivity timeouts */
ಶೂನ್ಯ channel_ಕೂಡಿಸು_timeout(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ದ್ವಿಗುಣ);
ಶೂನ್ಯ channel_clear_timeouts(ರಚನೆ ssh *);

/* mux proxy support */

ಪೂರ್ಣಾಂಕ	 channel_proxy_downstream(ರಚನೆ ssh *, Channel *mc);
ಪೂರ್ಣಾಂಕ	 channel_proxy_upstream(Channel *, ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);

/* protocol handler */

ಪೂರ್ಣಾಂಕ	 channel_ಒಳಹರಿವು_ದತ್ತಾಂಶ(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 channel_ಒಳಹರಿವು_extended_ದತ್ತಾಂಶ(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 channel_ಒಳಹರಿವು_ieof(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 channel_ಒಳಹರಿವು_oclose(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 channel_ಒಳಹರಿವು_open_confirmation(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 channel_ಒಳಹರಿವು_open_failure(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 channel_ಒಳಹರಿವು_ಕಿಟಕಿ_adjust(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 channel_ಒಳಹರಿವು_ಸ್ಥಿತಿ_confirm(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);

/* file descriptor handling (read/write) */
ರಚನೆ pollfd;
ರಚನೆ timespec;

ಶೂನ್ಯ	 channel_prepare_poll(ರಚನೆ ssh *, ರಚನೆ pollfd **,
	    u_int *, u_int *, u_int, ರಚನೆ timespec *);
ಶೂನ್ಯ	 channel_after_poll(ರಚನೆ ssh *, ರಚನೆ pollfd *, u_int);
ಪೂರ್ಣಾಂಕ	 channel_output_poll(ರಚನೆ ssh *);

ಪೂರ್ಣಾಂಕ      channel_not_very_much_buffered_ದತ್ತಾಂಶ(ರಚನೆ ssh *);
ಶೂನ್ಯ     channel_close_all(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ      channel_still_open(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 channel_tty_open(ರಚನೆ ssh *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *channel_format_extended_usage(ಸ್ಥಿರಾಂಕ Channel *);
ಅಕ್ಷರ	*channel_open_ಸಂದೇಶ(ರಚನೆ ssh *);
ಶೂನ್ಯ	 channel_report_open(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 channel_ಕಂಡುಹಿಡಿ_open(ರಚನೆ ssh *);

/* tcp forwarding */
ರಚನೆ Forward;
ರಚನೆ ForwardOptions;
ಶೂನ್ಯ	 channel_ಗಣ_af(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ af);
ಶೂನ್ಯ     channel_permit_all(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 channel_ಕೂಡಿಸು_permission(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 channel_clear_permission(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 channel_disable_admin(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 channel_update_permission(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
Channel	*channel_connect_ಗಮ್ಯ_ಪೋರ್ಟ್(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, u_short,
	    ಅಕ್ಷರ *, ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **);
Channel *channel_connect_ಗಮ್ಯ_ಮಾರ್ಗ(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *, ಅಕ್ಷರ *);
Channel	*channel_connect_stdio_fwd(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ*,
	    ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
Channel	*channel_connect_by_listen_ವಿಳಾಸ(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
	    u_short, ಅಕ್ಷರ *, ಅಕ್ಷರ *);
Channel	*channel_connect_by_listen_ಮಾರ್ಗ(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
	    ಅಕ್ಷರ *, ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 channel_request_remote_forwarding(ರಚನೆ ssh *, ರಚನೆ Forward *);
ಪೂರ್ಣಾಂಕ	 channel_ಸಿದ್ಧತೆ_local_fwd_listener(ರಚನೆ ssh *, ರಚನೆ Forward *,
	    ರಚನೆ ForwardOptions *);
ಪೂರ್ಣಾಂಕ	 channel_request_rforward_cancel(ರಚನೆ ssh *, ರಚನೆ Forward *);
ಪೂರ್ಣಾಂಕ	 channel_ಸಿದ್ಧತೆ_remote_fwd_listener(ರಚನೆ ssh *, ರಚನೆ Forward *,
	    ಪೂರ್ಣಾಂಕ *, ರಚನೆ ForwardOptions *);
ಪೂರ್ಣಾಂಕ	 channel_cancel_rport_listener(ರಚನೆ ssh *, ರಚನೆ Forward *);
ಪೂರ್ಣಾಂಕ	 channel_cancel_lport_listener(ರಚನೆ ssh *, ರಚನೆ Forward *,
	    ಪೂರ್ಣಾಂಕ, ರಚನೆ ForwardOptions *);
ಪೂರ್ಣಾಂಕ	 permitopen_ಪೋರ್ಟ್(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* x11 forwarding */

ಶೂನ್ಯ	 channel_ಗಣ_x11_refuse_ಸಮಯ(ರಚನೆ ssh *, ದ್ವಿಗುಣ);
ಪೂರ್ಣಾಂಕ	 x11_connect_display(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 x11_create_display_inet(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, u_int *, ಪೂರ್ಣಾಂಕ **);
ಶೂನ್ಯ	 x11_request_forwarding_with_spoofing(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ      x11_channel_ಬಳಸಿದ_recently(ರಚನೆ ssh *ssh);

/* channel close */

ಪೂರ್ಣಾಂಕ	 chan_is_dead(ರಚನೆ ssh *, Channel *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 chan_mark_dead(ರಚನೆ ssh *, Channel *);

/* agent forwarding */
ಶೂನ್ಯ	 client_channel_request_agent_forwarding(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);

/* channel events */

ಶೂನ್ಯ	 chan_rcvd_oclose(ರಚನೆ ssh *, Channel *);
ಶೂನ್ಯ	 chan_rcvd_eow(ರಚನೆ ssh *, Channel *);
ಶೂನ್ಯ	 chan_read_failed(ರಚನೆ ssh *, Channel *);
ಶೂನ್ಯ	 chan_ibuf_ಖಾಲಿಗಳು(ರಚನೆ ssh *, Channel *);
ಶೂನ್ಯ	 chan_rcvd_ieof(ರಚನೆ ssh *, Channel *);
ಶೂನ್ಯ	 chan_write_failed(ರಚನೆ ssh *, Channel *);
ಶೂನ್ಯ	 chan_obuf_ಖಾಲಿಗಳು(ರಚನೆ ssh *, Channel *);

#ಆದರೆ_ಅಂತ್ಯ
