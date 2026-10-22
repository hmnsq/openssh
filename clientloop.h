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

#ಅನ್ತರ್ಭಾವ <termios.h>

ರಚನೆ ssh;

/* Client side main loop for the interactive session. */
ಪೂರ್ಣಾಂಕ	 client_loop(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 client_x11_get_proto(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
	    u_int, u_int, ಅಕ್ಷರ **, ಅಕ್ಷರ **);
ಶೂನ್ಯ	 client_session2_ಸಿದ್ಧತೆ(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ termios *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *, ಅಕ್ಷರ **);
ಅಕ್ಷರ	 *client_request_tun_fwd(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ,
    channel_open_fn *, ಶೂನ್ಯ *);
ಶೂನ್ಯ	 client_stop_mux(ಶೂನ್ಯ);

/* Escape filter for protocol 2 sessions */
ಶೂನ್ಯ	*client_new_escape_filter_ctx(ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 client_filter_cleanup(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಶೂನ್ಯ *);
ಪೂರ್ಣಾಂಕ	 client_simple_escape_filter(ರಚನೆ ssh *, Channel *, ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);

/* Global request confirmation callbacks */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ global_confirm_cb(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, uint32_t, ಶೂನ್ಯ *);
ಶೂನ್ಯ	 client_ರಿಜಿಸ್ಟರ್_global_confirm(global_confirm_cb *, ಶೂನ್ಯ *);

/* Channel request confirmation callbacks */
ಎಣಿಕೆ confirm_action { CONFIRM_WARN = 0, CONFIRM_CLOSE, CONFIRM_TTY };
ಶೂನ್ಯ client_expect_confirm(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಎಣಿಕೆ confirm_action);

/* Multiplexing protocol version */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHMUX_VER			4

/* Multiplexing control protocol flags */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHMUX_COMMAND_OPEN		1	/* Open new connection */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHMUX_COMMAND_ALIVE_CHECK	2	/* Check master is alive */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHMUX_COMMAND_TERMINATE	3	/* Ask master to exit */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHMUX_COMMAND_STDIO_FWD	4	/* Open stdio fwd (ssh -W) */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHMUX_COMMAND_FORWARD		5	/* Forward only, no command */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHMUX_COMMAND_STOP		6	/* Disable mux but not conn */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHMUX_COMMAND_CANCEL_FWD	7	/* Cancel forwarding(s) */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHMUX_COMMAND_PROXY		8	/* Open new connection */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHMUX_COMMAND_CONNINFO		9	/* Show connection information */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHMUX_COMMAND_CHANINFO		10	/* Show channels information */

ಶೂನ್ಯ	muxserver_listen(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	muxclient(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	mux_exit_ಸಂದೇಶ(ರಚನೆ ssh *, Channel *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	mux_tty_alloc_failed(ರಚನೆ ssh *ssh, Channel *);

