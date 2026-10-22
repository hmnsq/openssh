/* $OpenBSD: clientloop.h,v 1.43 2026/09/23 21:42:39 djm Exp $ */

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
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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

#অন্তর্ভাব <termios.h>

কাঠামো ssh;

/* Client side main loop for the interactive session. */
পূর্ণসংখ্যা	 client_loop(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 client_x11_get_proto(কাঠামো ssh *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *,
	    u_int, u_int, অক্ষর **, অক্ষর **);
শূন্য	 client_session2_setup(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা,
	    ধ্রুবক অক্ষর *, কাঠামো termios *, পূর্ণসংখ্যা, কাঠামো sshbuf *, অক্ষর **);
অক্ষর	 *client_request_tun_fwd(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা,
    channel_open_fn *, শূন্য *);
শূন্য	 client_stop_mux(শূন্য);

/* Escape filter for protocol 2 sessions */
শূন্য	*client_new_escape_filter_ctx(পূর্ণসংখ্যা);
শূন্য	 client_filter_cleanup(কাঠামো ssh *, পূর্ণসংখ্যা, শূন্য *);
পূর্ণসংখ্যা	 client_simple_escape_filter(কাঠামো ssh *, Channel *, অক্ষর *, পূর্ণসংখ্যা);

/* Global request confirmation callbacks */
প্রকারলেখ শূন্য global_confirm_cb(কাঠামো ssh *, পূর্ণসংখ্যা, uint32_t, শূন্য *);
শূন্য	 client_register_global_confirm(global_confirm_cb *, শূন্য *);

/* Channel request confirmation callbacks */
গণনা confirm_action { CONFIRM_WARN = 0, CONFIRM_CLOSE, CONFIRM_TTY };
শূন্য client_expect_confirm(কাঠামো ssh *, পূর্ণসংখ্যা, ধ্রুবক অক্ষর *,
    গণনা confirm_action);

/* Multiplexing protocol version */
#define SSHMUX_VER			4

/* Multiplexing control protocol flags */
#define SSHMUX_COMMAND_OPEN		1	/* Open new connection */
#define SSHMUX_COMMAND_ALIVE_CHECK	2	/* Check master is alive */
#define SSHMUX_COMMAND_TERMINATE	3	/* Ask master to exit */
#define SSHMUX_COMMAND_STDIO_FWD	4	/* Open stdio fwd (ssh -W) */
#define SSHMUX_COMMAND_FORWARD		5	/* Forward only, no command */
#define SSHMUX_COMMAND_STOP		6	/* Disable mux but not conn */
#define SSHMUX_COMMAND_CANCEL_FWD	7	/* Cancel forwarding(s) */
#define SSHMUX_COMMAND_PROXY		8	/* Open new connection */
#define SSHMUX_COMMAND_CONNINFO		9	/* Show connection information */
#define SSHMUX_COMMAND_CHANINFO		10	/* Show channels information */

শূন্য	muxserver_listen(কাঠামো ssh *);
পূর্ণসংখ্যা	muxclient(ধ্রুবক অক্ষর *);
শূন্য	mux_exit_message(কাঠামো ssh *, Channel *, পূর্ণসংখ্যা);
শূন্য	mux_tty_alloc_failed(কাঠামো ssh *ssh, Channel *);

