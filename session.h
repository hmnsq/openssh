/* $OpenBSD: session.h,v 1.37 2023/01/06 02:39:59 djm Exp $ */

/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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
#ifndef SESSION_H
#define SESSION_H

#define TTYSZ 64
ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା Session Session;
ସଂରଚନା Session {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	used;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	self;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	next_unused;
	ସଂରଚନା passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	forced;

	/* tty */
	ଅକ୍ଷର	*term;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ptyfd, ttyfd, ptymaster;
	u_int	row, col, xpixel, ypixel;
	ଅକ୍ଷର	tty[TTYSZ];

	/* X11 */
	u_int	display_ସଂଖ୍ୟା;
	ଅକ୍ଷର	*display;
	u_int	screen;
	ଅକ୍ଷର	*auth_display;
	ଅକ୍ଷର	*auth_proto;
	ଅକ୍ଷର	*auth_data;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	single_connection;

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	chanid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	*x11_chanids;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	is_subsystem;
	ଅକ୍ଷର	*subsys;
	u_int	ଅଙ୍କ_env;
	ସଂରଚନା {
		ଅକ୍ଷର	*name;
		ଅକ୍ଷର	*val;
	} *env;
};

ଶୂନ୍ୟ	 do_authenticated(ସଂରଚନା ssh *, Authctxt *);
ଶୂନ୍ୟ	 do_cleanup(ସଂରଚନା ssh *, Authctxt *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 session_open(Authctxt *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 session_unused(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 session_ନିବେଶ_channel_req(ସଂରଚନା ssh *, Channel *, ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ	 session_close_by_pid(ସଂରଚନା ssh *ssh, pid_t, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 session_close_by_channel(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଶୂନ୍ୟ *);
ଶୂନ୍ୟ	 session_destroy_all(ସଂରଚନା ssh *, ଶୂନ୍ୟ (*)(Session *));
ଶୂନ୍ୟ	 session_pty_cleanup2(Session *);

Session	*session_new(ଶୂନ୍ୟ);
Session	*session_by_tty(ଅକ୍ଷର *);
ଶୂନ୍ୟ	 session_close(ସଂରଚନା ssh *, Session *);
ଶୂନ୍ୟ	 do_setusercontext(ସଂରଚନା passwd *);

ଅଚଳ ଅକ୍ଷର	*session_get_remote_name_or_ip(ସଂରଚନା ssh *, u_int, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

#endif
