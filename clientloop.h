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

#समावेश <termios.h>

काष्ठा ssh;

/* Client side main loop for the interactive session. */
पूर्णांक	 client_loop(काष्ठा ssh *, पूर्णांक, पूर्णांक, पूर्णांक);
पूर्णांक	 client_x11_get_proto(काष्ठा ssh *, स्थिर अक्षर *, स्थिर अक्षर *,
	    u_int, u_int, अक्षर **, अक्षर **);
व्योम	 client_session2_setup(काष्ठा ssh *, पूर्णांक, पूर्णांक, पूर्णांक,
	    स्थिर अक्षर *, काष्ठा termios *, पूर्णांक, काष्ठा sshbuf *, अक्षर **);
अक्षर	 *client_request_tun_fwd(काष्ठा ssh *, पूर्णांक, पूर्णांक, पूर्णांक,
    channel_open_fn *, व्योम *);
व्योम	 client_stop_mux(व्योम);

/* Escape filter for protocol 2 sessions */
व्योम	*client_new_escape_filter_ctx(पूर्णांक);
व्योम	 client_filter_cleanup(काष्ठा ssh *, पूर्णांक, व्योम *);
पूर्णांक	 client_simple_escape_filter(काष्ठा ssh *, Channel *, अक्षर *, पूर्णांक);

/* Global request confirmation callbacks */
प्रकार व्योम global_confirm_cb(काष्ठा ssh *, पूर्णांक, uint32_t, व्योम *);
व्योम	 client_register_global_confirm(global_confirm_cb *, व्योम *);

/* Channel request confirmation callbacks */
क्रमागत confirm_action { CONFIRM_WARN = 0, CONFIRM_CLOSE, CONFIRM_TTY };
व्योम client_expect_confirm(काष्ठा ssh *, पूर्णांक, स्थिर अक्षर *,
    क्रमागत confirm_action);

/* Multiplexing protocol version */
#घोषणा SSHMUX_VER			4

/* Multiplexing control protocol flags */
#घोषणा SSHMUX_COMMAND_OPEN		1	/* Open new connection */
#घोषणा SSHMUX_COMMAND_ALIVE_CHECK	2	/* Check master is alive */
#घोषणा SSHMUX_COMMAND_TERMINATE	3	/* Ask master to exit */
#घोषणा SSHMUX_COMMAND_STDIO_FWD	4	/* Open stdio fwd (ssh -W) */
#घोषणा SSHMUX_COMMAND_FORWARD		5	/* Forward only, no command */
#घोषणा SSHMUX_COMMAND_STOP		6	/* Disable mux but not conn */
#घोषणा SSHMUX_COMMAND_CANCEL_FWD	7	/* Cancel forwarding(s) */
#घोषणा SSHMUX_COMMAND_PROXY		8	/* Open new connection */
#घोषणा SSHMUX_COMMAND_CONNINFO		9	/* Show connection information */
#घोषणा SSHMUX_COMMAND_CHANINFO		10	/* Show channels information */

व्योम	muxserver_listen(काष्ठा ssh *);
पूर्णांक	muxclient(स्थिर अक्षर *);
व्योम	mux_exit_message(काष्ठा ssh *, Channel *, पूर्णांक);
व्योम	mux_tty_alloc_failed(काष्ठा ssh *ssh, Channel *);

