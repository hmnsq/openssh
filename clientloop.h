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

#અન્તર્ભાવ <termios.h>

સંરચના ssh;

/* Client side main loop for the interactive session. */
પૂર્ણાંક	 client_loop(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક);
પૂર્ણાંક	 client_x11_get_proto(સંરચના ssh *, અચલ અક્ષર *, અચલ અક્ષર *,
	    u_int, u_int, અક્ષર **, અક્ષર **);
શૂન્ય	 client_session2_setup(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક,
	    અચલ અક્ષર *, સંરચના termios *, પૂર્ણાંક, સંરચના sshbuf *, અક્ષર **);
અક્ષર	 *client_request_tun_fwd(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક,
    channel_open_fn *, શૂન્ય *);
શૂન્ય	 client_stop_mux(શૂન્ય);

/* Escape filter for protocol 2 sessions */
શૂન્ય	*client_new_escape_filter_ctx(પૂર્ણાંક);
શૂન્ય	 client_filter_cleanup(સંરચના ssh *, પૂર્ણાંક, શૂન્ય *);
પૂર્ણાંક	 client_simple_escape_filter(સંરચના ssh *, Channel *, અક્ષર *, પૂર્ણાંક);

/* Global request confirmation callbacks */
પ્રકારવ્યાખ્યા શૂન્ય global_confirm_cb(સંરચના ssh *, પૂર્ણાંક, uint32_t, શૂન્ય *);
શૂન્ય	 client_register_global_confirm(global_confirm_cb *, શૂન્ય *);

/* Channel request confirmation callbacks */
ગણના confirm_action { CONFIRM_WARN = 0, CONFIRM_CLOSE, CONFIRM_TTY };
શૂન્ય client_expect_confirm(સંરચના ssh *, પૂર્ણાંક, અચલ અક્ષર *,
    ગણના confirm_action);

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

શૂન્ય	muxserver_listen(સંરચના ssh *);
પૂર્ણાંક	muxclient(અચલ અક્ષર *);
શૂન્ય	mux_exit_message(સંરચના ssh *, Channel *, પૂર્ણાંક);
શૂન્ય	mux_tty_alloc_failed(સંરચના ssh *ssh, Channel *);

