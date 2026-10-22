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

#അന്തര്ഭാവ <termios.h>

ഘടന ssh;

/* Client side main loop for the interactive session. */
പൂർണ്ണസംഖ്യ	 client_loop(ഘടന ssh *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 client_x11_get_proto(ഘടന ssh *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *,
	    u_int, u_int, അക്ഷരം **, അക്ഷരം **);
ശൂന്യം	 client_session2_setup(ഘടന ssh *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ,
	    സ്ഥിരം അക്ഷരം *, ഘടന termios *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *, അക്ഷരം **);
അക്ഷരം	 *client_request_tun_fwd(ഘടന ssh *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ,
    channel_open_fn *, ശൂന്യം *);
ശൂന്യം	 client_stop_mux(ശൂന്യം);

/* Escape filter for protocol 2 sessions */
ശൂന്യം	*client_new_escape_filter_ctx(പൂർണ്ണസംഖ്യ);
ശൂന്യം	 client_filter_cleanup(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ശൂന്യം *);
പൂർണ്ണസംഖ്യ	 client_simple_escape_filter(ഘടന ssh *, Channel *, അക്ഷരം *, പൂർണ്ണസംഖ്യ);

/* Global request confirmation callbacks */
തരനിർവചനം ശൂന്യം global_confirm_cb(ഘടന ssh *, പൂർണ്ണസംഖ്യ, uint32_t, ശൂന്യം *);
ശൂന്യം	 client_register_global_confirm(global_confirm_cb *, ശൂന്യം *);

/* Channel request confirmation callbacks */
എണ്ണൽ confirm_action { CONFIRM_WARN = 0, CONFIRM_CLOSE, CONFIRM_TTY };
ശൂന്യം client_expect_confirm(ഘടന ssh *, പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *,
    എണ്ണൽ confirm_action);

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

ശൂന്യം	muxserver_listen(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	muxclient(സ്ഥിരം അക്ഷരം *);
ശൂന്യം	mux_exit_message(ഘടന ssh *, Channel *, പൂർണ്ണസംഖ്യ);
ശൂന്യം	mux_tty_alloc_failed(ഘടന ssh *ssh, Channel *);

