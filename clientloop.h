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

#ضمن <termios.h>

بنية ssh;

/* Client side main loop for the interactive session. */
صحيح	 client_loop(بنية ssh *, صحيح, صحيح, صحيح);
صحيح	 client_x11_get_proto(بنية ssh *, ثابت حرف *, ثابت حرف *,
	    u_int, u_int, حرف **, حرف **);
فراغ	 client_session2_تیاری(بنية ssh *, صحيح, صحيح, صحيح,
	    ثابت حرف *, بنية termios *, صحيح, بنية sshbuf *, حرف **);
حرف	 *client_request_tun_fwd(بنية ssh *, صحيح, صحيح, صحيح,
    channel_open_fn *, فراغ *);
فراغ	 client_stop_mux(فراغ);

/* Escape filter for protocol 2 sessions */
فراغ	*client_new_escape_filter_ctx(صحيح);
فراغ	 client_filter_cleanup(بنية ssh *, صحيح, فراغ *);
صحيح	 client_simple_escape_filter(بنية ssh *, Channel *, حرف *, صحيح);

/* Global request confirmation callbacks */
تعريفنوع فراغ global_confirm_cb(بنية ssh *, صحيح, uint32_t, فراغ *);
فراغ	 client_رجسٹر_global_confirm(global_confirm_cb *, فراغ *);

/* Channel request confirmation callbacks */
تعداد confirm_action { CONFIRM_WARN = 0, CONFIRM_CLOSE, CONFIRM_TTY };
فراغ client_expect_confirm(بنية ssh *, صحيح, ثابت حرف *,
    تعداد confirm_action);

/* Multiplexing protocol version */
#تعریف_کرو SSHMUX_VER			4

/* Multiplexing control protocol flags */
#تعریف_کرو SSHMUX_COMMAND_OPEN		1	/* Open new connection */
#تعریف_کرو SSHMUX_COMMAND_ALIVE_CHECK	2	/* Check master is alive */
#تعریف_کرو SSHMUX_COMMAND_TERMINATE	3	/* Ask master to exit */
#تعریف_کرو SSHMUX_COMMAND_STDIO_FWD	4	/* Open stdio fwd (ssh -W) */
#تعریف_کرو SSHMUX_COMMAND_FORWARD		5	/* Forward only, no command */
#تعریف_کرو SSHMUX_COMMAND_STOP		6	/* Disable mux but not conn */
#تعریف_کرو SSHMUX_COMMAND_CANCEL_FWD	7	/* Cancel forwarding(s) */
#تعریف_کرو SSHMUX_COMMAND_PROXY		8	/* Open new connection */
#تعریف_کرو SSHMUX_COMMAND_CONNINFO		9	/* Show connection information */
#تعریف_کرو SSHMUX_COMMAND_CHANINFO		10	/* Show channels information */

فراغ	muxserver_listen(بنية ssh *);
صحيح	muxclient(ثابت حرف *);
فراغ	mux_exit_سنیہا(بنية ssh *, Channel *, صحيح);
فراغ	mux_tty_alloc_failed(بنية ssh *ssh, Channel *);

