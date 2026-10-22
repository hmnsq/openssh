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

#अन्तर्भाव <termios.h>

संरचना ssh;

/* Client side main loop for the interactive session. */
पूर्णांक	 client_loop(संरचना ssh *, पूर्णांक, पूर्णांक, पूर्णांक);
पूर्णांक	 client_x11_get_proto(संरचना ssh *, स्थिरांक अक्षर *, स्थिरांक अक्षर *,
	    u_int, u_int, अक्षर **, अक्षर **);
शून्य	 client_session2_setup(संरचना ssh *, पूर्णांक, पूर्णांक, पूर्णांक,
	    स्थिरांक अक्षर *, संरचना termios *, पूर्णांक, संरचना sshbuf *, अक्षर **);
अक्षर	 *client_request_tun_fwd(संरचना ssh *, पूर्णांक, पूर्णांक, पूर्णांक,
    channel_open_fn *, शून्य *);
शून्य	 client_stop_mux(शून्य);

/* Escape filter for protocol 2 sessions */
शून्य	*client_new_escape_filter_ctx(पूर्णांक);
शून्य	 client_filter_cleanup(संरचना ssh *, पूर्णांक, शून्य *);
पूर्णांक	 client_simple_escape_filter(संरचना ssh *, Channel *, अक्षर *, पूर्णांक);

/* Global request confirmation callbacks */
प्रकारव्याख्या शून्य global_confirm_cb(संरचना ssh *, पूर्णांक, uint32_t, शून्य *);
शून्य	 client_register_global_confirm(global_confirm_cb *, शून्य *);

/* Channel request confirmation callbacks */
गणना confirm_action { CONFIRM_WARN = 0, CONFIRM_CLOSE, CONFIRM_TTY };
शून्य client_expect_confirm(संरचना ssh *, पूर्णांक, स्थिरांक अक्षर *,
    गणना confirm_action);

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

शून्य	muxserver_listen(संरचना ssh *);
पूर्णांक	muxclient(स्थिरांक अक्षर *);
शून्य	mux_exit_message(संरचना ssh *, Channel *, पूर्णांक);
शून्य	mux_tty_alloc_failed(संरचना ssh *ssh, Channel *);

