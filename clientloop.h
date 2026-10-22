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

#అన్తర్భావ <termios.h>

నిర్మాణం ssh;

/* Client side main loop for the interactive session. */
పూర్ణాంకం	 client_loop(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం);
పూర్ణాంకం	 client_x11_get_proto(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
	    u_int, u_int, అక్షరం **, అక్షరం **);
శూన్య	 client_session2_అమరిక(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం,
	    స్థిరరాశి అక్షరం *, నిర్మాణం termios *, పూర్ణాంకం, నిర్మాణం sshbuf *, అక్షరం **);
అక్షరం	 *client_request_tun_fwd(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం,
    channel_open_fn *, శూన్య *);
శూన్య	 client_stop_mux(శూన్య);

/* Escape filter for protocol 2 sessions */
శూన్య	*client_new_escape_filter_ctx(పూర్ణాంకం);
శూన్య	 client_filter_cleanup(నిర్మాణం ssh *, పూర్ణాంకం, శూన్య *);
పూర్ణాంకం	 client_simple_escape_filter(నిర్మాణం ssh *, Channel *, అక్షరం *, పూర్ణాంకం);

/* Global request confirmation callbacks */
రకనిర్వచనం శూన్య global_confirm_cb(నిర్మాణం ssh *, పూర్ణాంకం, uint32_t, శూన్య *);
శూన్య	 client_రిజిస్టరు_global_confirm(global_confirm_cb *, శూన్య *);

/* Channel request confirmation callbacks */
గణన confirm_action { CONFIRM_WARN = 0, CONFIRM_CLOSE, CONFIRM_TTY };
శూన్య client_expect_confirm(నిర్మాణం ssh *, పూర్ణాంకం, స్థిరరాశి అక్షరం *,
    గణన confirm_action);

/* Multiplexing protocol version */
#నిర్వచించు SSHMUX_VER			4

/* Multiplexing control protocol flags */
#నిర్వచించు SSHMUX_COMMAND_OPEN		1	/* Open new connection */
#నిర్వచించు SSHMUX_COMMAND_ALIVE_CHECK	2	/* Check master is alive */
#నిర్వచించు SSHMUX_COMMAND_TERMINATE	3	/* Ask master to exit */
#నిర్వచించు SSHMUX_COMMAND_STDIO_FWD	4	/* Open stdio fwd (ssh -W) */
#నిర్వచించు SSHMUX_COMMAND_FORWARD		5	/* Forward only, no command */
#నిర్వచించు SSHMUX_COMMAND_STOP		6	/* Disable mux but not conn */
#నిర్వచించు SSHMUX_COMMAND_CANCEL_FWD	7	/* Cancel forwarding(s) */
#నిర్వచించు SSHMUX_COMMAND_PROXY		8	/* Open new connection */
#నిర్వచించు SSHMUX_COMMAND_CONNINFO		9	/* Show connection information */
#నిర్వచించు SSHMUX_COMMAND_CHANINFO		10	/* Show channels information */

శూన్య	muxserver_listen(నిర్మాణం ssh *);
పూర్ణాంకం	muxclient(స్థిరరాశి అక్షరం *);
శూన్య	mux_exit_సందేశం(నిర్మాణం ssh *, Channel *, పూర్ణాంకం);
శూన్య	mux_tty_alloc_failed(నిర్మాణం ssh *ssh, Channel *);

