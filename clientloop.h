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

#ਅਨ੍ਤਰ੍ਭਾਵ <termios.h>

ਬਣਤਰ ssh;

/* Client side main loop for the interactive session. */
ਪੂਰਨ	 client_loop(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ);
ਪੂਰਨ	 client_x11_get_proto(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
	    u_int, u_int, ਅੱਖਰ **, ਅੱਖਰ **);
ਖਾਲੀ	 client_session2_ਤਿਆਰੀ(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ,
	    ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ termios *, ਪੂਰਨ, ਬਣਤਰ sshbuf *, ਅੱਖਰ **);
ਅੱਖਰ	 *client_request_tun_fwd(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ,
    channel_open_fn *, ਖਾਲੀ *);
ਖਾਲੀ	 client_stop_mux(ਖਾਲੀ);

/* Escape filter for protocol 2 sessions */
ਖਾਲੀ	*client_new_escape_filter_ctx(ਪੂਰਨ);
ਖਾਲੀ	 client_filter_cleanup(ਬਣਤਰ ssh *, ਪੂਰਨ, ਖਾਲੀ *);
ਪੂਰਨ	 client_simple_escape_filter(ਬਣਤਰ ssh *, Channel *, ਅੱਖਰ *, ਪੂਰਨ);

/* Global request confirmation callbacks */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ global_confirm_cb(ਬਣਤਰ ssh *, ਪੂਰਨ, uint32_t, ਖਾਲੀ *);
ਖਾਲੀ	 client_ਰਜਿਸਟਰ_global_confirm(global_confirm_cb *, ਖਾਲੀ *);

/* Channel request confirmation callbacks */
ਗਿਣਤੀ confirm_action { CONFIRM_WARN = 0, CONFIRM_CLOSE, CONFIRM_TTY };
ਖਾਲੀ client_expect_confirm(ਬਣਤਰ ssh *, ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *,
    ਗਿਣਤੀ confirm_action);

/* Multiplexing protocol version */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHMUX_VER			4

/* Multiplexing control protocol flags */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHMUX_COMMAND_OPEN		1	/* Open new connection */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHMUX_COMMAND_ALIVE_CHECK	2	/* Check master is alive */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHMUX_COMMAND_TERMINATE	3	/* Ask master to exit */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHMUX_COMMAND_STDIO_FWD	4	/* Open stdio fwd (ssh -W) */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHMUX_COMMAND_FORWARD		5	/* Forward only, no command */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHMUX_COMMAND_STOP		6	/* Disable mux but not conn */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHMUX_COMMAND_CANCEL_FWD	7	/* Cancel forwarding(s) */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHMUX_COMMAND_PROXY		8	/* Open new connection */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHMUX_COMMAND_CONNINFO		9	/* Show connection information */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHMUX_COMMAND_CHANINFO		10	/* Show channels information */

ਖਾਲੀ	muxserver_listen(ਬਣਤਰ ssh *);
ਪੂਰਨ	muxclient(ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	mux_exit_ਸੁਨੇਹਾ(ਬਣਤਰ ssh *, Channel *, ਪੂਰਨ);
ਖਾਲੀ	mux_tty_alloc_failed(ਬਣਤਰ ssh *ssh, Channel *);

