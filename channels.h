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

ସଂରଚନା ssh;
ସଂରଚନା Channel;
ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା Channel Channel;
ସଂରଚନା channel_connect;

ପ୍ରକାରବ୍ୟାଖ୍ୟା ଶୂନ୍ୟ channel_open_fn(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଶୂନ୍ୟ *);
ପ୍ରକାରବ୍ୟାଖ୍ୟା ଶୂନ୍ୟ channel_callback_fn(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଶୂନ୍ୟ *);
ପ୍ରକାରବ୍ୟାଖ୍ୟା ପୂର୍ଣ୍ଣସଂଖ୍ୟା channel_infilter_fn(ସଂରଚନା ssh *, ସଂରଚନା Channel *, ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପ୍ରକାରବ୍ୟାଖ୍ୟା ଶୂନ୍ୟ channel_filter_cleanup_fn(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଶୂନ୍ୟ *);
ପ୍ରକାରବ୍ୟାଖ୍ୟା u_char *channel_outfilter_fn(ସଂରଚନା ssh *, ସଂରଚନା Channel *,
    u_char **, size_t *);

/* Channel success/failure callbacks */
ପ୍ରକାରବ୍ୟାଖ୍ୟା ଶୂନ୍ୟ channel_confirm_cb(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା Channel *, ଶୂନ୍ୟ *);
ପ୍ରକାରବ୍ୟାଖ୍ୟା ଶୂନ୍ୟ channel_confirm_abandon_cb(ସଂରଚନା ssh *, ସଂରଚନା Channel *, ଶୂନ୍ୟ *);
ସଂରଚନା channel_confirm {
	TAILQ_ENTRY(channel_confirm) entry;
	channel_confirm_cb *cb;
	channel_confirm_abandon_cb *abandon_cb;
	ଶୂନ୍ୟ *ctx;
};
TAILQ_HEAD(channel_confirms, channel_confirm);

/* Callbacks for mux channels back into client-specific code */
ପ୍ରକାରବ୍ୟାଖ୍ୟା ପୂର୍ଣ୍ଣସଂଖ୍ୟା mux_callback_fn(ସଂରଚନା ssh *, ସଂରଚନା Channel *);

/*
 * NB. channel IDs on the wire and in c->remote_id are uint32, but local
 * channel IDs (e.g. c->self) only ever use the int32 subset of this range,
 * because we use local channel ID -1 for housekeeping. Remote channels have
 * a dedicated "have_remote_id" flag to indicate their validity.
 */

ସଂରଚନା Channel {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     type;		/* channel type/state */

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     self;		/* my own channel identifier */
	uint32_t remote_id;	/* channel identifier for remote peer */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	have_remote_id;	/* non-zero if remote_id is valid */

	u_int   istate;		/* input from channel (state of receive half) */
	u_int   ostate;		/* output to channel  (state of transmit half) */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     flags;		/* close sent/rcvd */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     rfd;		/* read fd */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     wfd;		/* write fd */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     efd;		/* extended fd */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     sock;		/* sock fd */
	u_int	io_want;	/* bitmask of SSH_CHAN_IO_* */
	u_int	io_ready;	/* bitmask of SSH_CHAN_IO_* */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	pfds[4];	/* pollfd entries for rfd/wfd/efd/sock */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     ctl_chan;	/* control channel (multiplexed connections) */
	uint32_t ctl_child_id;	/* child session for mux controllers */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	have_ctl_child_id;/* non-zero if ctl_child_id is valid */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     remote_has_tty;	/* remote side has a tty */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     isatty;		/* rfd is a tty */
#ifdef _AIX
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     wfd_isatty;	/* wfd is a tty */
#endif
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	client_tty;	/* (client) TTY has been requested */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     force_drain;	/* force close on iEOF */
	ଦ୍ୱିଗୁଣ	notbefore;	/* Pause IO until deadline (time_t) */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     delayed;	/* post-IO handlers for newly created
				 * channels are delayed until the first call
				 * to a matching pre-IO handler.
				 * this way post-IO handlers are not
				 * accidentally called if a FD gets reused */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	restore_block;	/* fd mask to restore blocking status */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	restore_flags[3];/* flags to restore */
	ସଂରଚନା sshbuf *ନିବେଶ;	/* data read from socket, to be sent over
				 * encrypted connection */
	ସଂରଚନା sshbuf *output;	/* data received over encrypted connection for
				 * send on socket */
	ସଂରଚନା sshbuf *extended;

	ଅକ୍ଷର    *path;
		/* path for unix domain sockets, or host name for forwards */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     listening_port;	/* port being listened for forwards */
	ଅକ୍ଷର   *listening_addr;	/* addr being listened for forwards */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     host_port;	/* remote port to connect for forwards */
	ଅକ୍ଷର   *remote_name;	/* remote hostname */

	u_int	remote_window;
	u_int	remote_maxpacket;
	u_int	local_window;
	u_int	local_window_exceeded;
	u_int	local_window_max;
	u_int	local_consumed;
	u_int	local_maxpacket;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     extended_usage;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	agent_new;	/* For agent listeners, use RFC 9987 requests */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	single_connection;

	ଅକ୍ଷର   *ctype;		/* const type - NB. not freed on channel_free */
	ଅକ୍ଷର   *xctype;		/* extended type */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	bulk;		/* channel is non-interactive */

	/* callback */
	channel_open_fn		*open_confirm;
	ଶୂନ୍ୟ			*open_confirm_ctx;
	channel_callback_fn	*detach_user;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			detach_close;
	ସଂରଚନା channel_confirms	status_confirms;

	/* filter */
	channel_infilter_fn	*ନିବେଶ_filter;
	channel_outfilter_fn	*output_filter;
	ଶୂନ୍ୟ			*filter_ctx;
	channel_filter_cleanup_fn *filter_cleanup;

	/* keep boundaries */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			datagram;

	/* non-blocking connect */
	ସଂରଚନା channel_connect	*connect_ctx;

	/* multiplexing protocol hook, called for each packet received */
	mux_callback_fn		*mux_rcb;
	ଶୂନ୍ୟ			*mux_ctx;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			mux_pause;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			mux_downstream_id;

	/* Inactivity timeouts */

	/* Last traffic seen for OPEN channels */
	ଦ୍ୱିଗୁଣ			lastused;
	/* Inactivity timeout deadline in seconds (0 = no timeout) */
	ଦ୍ୱିଗୁଣ			inactive_deadline;
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
#define CHAN_ନିବେଶ_OPEN			0
#define CHAN_ନିବେଶ_WAIT_DRAIN		1
#define CHAN_ନିବେଶ_WAIT_OCLOSE		2
#define CHAN_ନିବେଶ_CLOSED		3

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
#define CHAN_ନିବେଶ_MAX	(16*1024*1024)

/* Hard limit on number of channels */
#define CHANNELS_MAX_CHANNELS	(16*1024)

/* check whether 'efd' is still in use */
#define CHANNEL_EFD_ନିବେଶ_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_READ && \
	(c->efd != -1 || \
	sshbuf_len(c->extended) > 0))
#define CHANNEL_EFD_OUTPUT_ACTIVE(c) \
	(c->extended_usage == CHAN_EXTENDED_WRITE && \
	c->efd != -1 && (!(c->flags & (CHAN_EOF_RCVD|CHAN_CLOSE_RCVD)) || \
	sshbuf_len(c->extended) > 0))

/* Add/remove channel management structures to/from SSH transport instance */
ଶୂନ୍ୟ channel_init_channels(ସଂରଚନା ssh *ssh);
ଶୂନ୍ୟ channel_free_channels(ସଂରଚନା ssh *ssh);

/* channel management */

Channel	*channel_by_id(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
Channel	*channel_by_remote_id(ସଂରଚନା ssh *, u_int);
Channel	*channel_lookup(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
Channel *channel_new(ସଂରଚନା ssh *, ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
	    u_int, u_int, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 channel_set_fds(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
	    ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, u_int);
ଶୂନ୍ୟ	 channel_set_tty(ସଂରଚନା ssh *, Channel *);
ଶୂନ୍ୟ	 channel_free(ସଂରଚନା ssh *, Channel *);
ଶୂନ୍ୟ	 channel_free_all(ସଂରଚନା ssh *);
ଶୂନ୍ୟ	 channel_stop_listening(ସଂରଚନା ssh *);
ଶୂନ୍ୟ	 channel_force_close(ସଂରଚନା ssh *, Channel *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 channel_set_xtype(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *);

ଶୂନ୍ୟ	 channel_send_open(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 channel_request_start(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 channel_register_cleanup(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
	    channel_callback_fn *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 channel_register_open_confirm(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
	    channel_open_fn *, ଶୂନ୍ୟ *);
ଶୂନ୍ୟ	 channel_register_filter(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, channel_infilter_fn *,
	    channel_outfilter_fn *, channel_filter_cleanup_fn *, ଶୂନ୍ୟ *);
ଶୂନ୍ୟ	 channel_register_status_confirm(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
	    channel_confirm_cb *, channel_confirm_abandon_cb *, ଶୂନ୍ୟ *);
ଶୂନ୍ୟ	 channel_cancel_cleanup(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_close_fd(ସଂରଚନା ssh *, Channel *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
ଶୂନ୍ୟ	 channel_send_window_changes(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_has_bulk(ସଂରଚନା ssh *);
ଶୂନ୍ୟ	 channel_set_tcp_keepalives(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/* channel inactivity timeouts */
ଶୂନ୍ୟ channel_add_timeout(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *, ଦ୍ୱିଗୁଣ);
ଶୂନ୍ୟ channel_clear_timeouts(ସଂରଚନା ssh *);

/* mux proxy support */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_proxy_downstream(ସଂରଚନା ssh *, Channel *mc);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_proxy_upstream(Channel *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);

/* protocol handler */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_ନିବେଶ_data(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_ନିବେଶ_extended_data(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_ନିବେଶ_ieof(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_ନିବେଶ_oclose(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_ନିବେଶ_open_confirmation(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_ନିବେଶ_open_failure(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_ନିବେଶ_window_adjust(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_ନିବେଶ_status_confirm(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);

/* file descriptor handling (read/write) */
ସଂରଚନା pollfd;
ସଂରଚନା timespec;

ଶୂନ୍ୟ	 channel_prepare_poll(ସଂରଚନା ssh *, ସଂରଚନା pollfd **,
	    u_int *, u_int *, u_int, ସଂରଚନା timespec *);
ଶୂନ୍ୟ	 channel_after_poll(ସଂରଚନା ssh *, ସଂରଚନା pollfd *, u_int);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_output_poll(ସଂରଚନା ssh *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା      channel_not_very_much_buffered_data(ସଂରଚନା ssh *);
ଶୂନ୍ୟ     channel_close_all(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା      channel_still_open(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_tty_open(ସଂରଚନା ssh *);
ଅଚଳ ଅକ୍ଷର *channel_format_extended_usage(ଅଚଳ Channel *);
ଅକ୍ଷର	*channel_open_message(ସଂରଚନା ssh *);
ଶୂନ୍ୟ	 channel_report_open(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_find_open(ସଂରଚନା ssh *);

/* tcp forwarding */
ସଂରଚନା Forward;
ସଂରଚନା ForwardOptions;
ଶୂନ୍ୟ	 channel_set_af(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା af);
ଶୂନ୍ୟ     channel_permit_all(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 channel_add_permission(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 channel_clear_permission(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 channel_disable_admin(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 channel_update_permission(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
Channel	*channel_connect_to_port(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *, u_short,
	    ଅକ୍ଷର *, ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ଅଚଳ ଅକ୍ଷର **);
Channel *channel_connect_to_path(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *, ଅକ୍ଷର *, ଅକ୍ଷର *);
Channel	*channel_connect_stdio_fwd(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର*,
	    ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
Channel	*channel_connect_by_listen_address(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *,
	    u_short, ଅକ୍ଷର *, ଅକ୍ଷର *);
Channel	*channel_connect_by_listen_path(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *,
	    ଅକ୍ଷର *, ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_request_remote_forwarding(ସଂରଚନା ssh *, ସଂରଚନା Forward *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_setup_local_fwd_listener(ସଂରଚନା ssh *, ସଂରଚନା Forward *,
	    ସଂରଚନା ForwardOptions *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_request_rforward_cancel(ସଂରଚନା ssh *, ସଂରଚନା Forward *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_setup_remote_fwd_listener(ସଂରଚନା ssh *, ସଂରଚନା Forward *,
	    ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ସଂରଚନା ForwardOptions *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_cancel_rport_listener(ସଂରଚନା ssh *, ସଂରଚନା Forward *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 channel_cancel_lport_listener(ସଂରଚନା ssh *, ସଂରଚନା Forward *,
	    ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା ForwardOptions *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 permitopen_port(ଅଚଳ ଅକ୍ଷର *);

/* x11 forwarding */

ଶୂନ୍ୟ	 channel_set_x11_refuse_time(ସଂରଚନା ssh *, ଦ୍ୱିଗୁଣ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 x11_connect_display(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 x11_create_display_inet(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, u_int *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା **);
ଶୂନ୍ୟ	 x11_request_forwarding_with_spoofing(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
	    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା      x11_channel_used_recently(ସଂରଚନା ssh *ssh);

/* channel close */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 chan_is_dead(ସଂରଚନା ssh *, Channel *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 chan_mark_dead(ସଂରଚନା ssh *, Channel *);

/* agent forwarding */
ଶୂନ୍ୟ	 client_channel_request_agent_forwarding(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/* channel events */

ଶୂନ୍ୟ	 chan_rcvd_oclose(ସଂରଚନା ssh *, Channel *);
ଶୂନ୍ୟ	 chan_rcvd_eow(ସଂରଚନା ssh *, Channel *);
ଶୂନ୍ୟ	 chan_read_failed(ସଂରଚନା ssh *, Channel *);
ଶୂନ୍ୟ	 chan_ibuf_empty(ସଂରଚନା ssh *, Channel *);
ଶୂନ୍ୟ	 chan_rcvd_ieof(ସଂରଚନା ssh *, Channel *);
ଶୂନ୍ୟ	 chan_write_failed(ସଂରଚନା ssh *, Channel *);
ଶୂନ୍ୟ	 chan_obuf_empty(ସଂରଚନା ssh *, Channel *);

#endif
