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
ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ Session Session;
ಸಂರಚನಾ Session {
	ಪೂರ್ಣಾಙ್ಕ	used;
	ಪೂರ್ಣಾಙ್ಕ	self;
	ಪೂರ್ಣಾಙ್ಕ	next_unused;
	ಸಂರಚನಾ passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	ಪೂರ್ಣಾಙ್ಕ	forced;

	/* tty */
	ವರ್ಣ	*term;
	ಪೂರ್ಣಾಙ್ಕ	ptyfd, ttyfd, ptymaster;
	u_int	row, col, xpixel, ypixel;
	ವರ್ಣ	tty[TTYSZ];

	/* X11 */
	u_int	display_ಸಂಖ್ಯೆ;
	ವರ್ಣ	*display;
	u_int	screen;
	ವರ್ಣ	*auth_display;
	ವರ್ಣ	*auth_proto;
	ವರ್ಣ	*auth_data;
	ಪೂರ್ಣಾಙ್ಕ	single_connection;

	ಪೂರ್ಣಾಙ್ಕ	chanid;
	ಪೂರ್ಣಾಙ್ಕ	*x11_chanids;
	ಪೂರ್ಣಾಙ್ಕ	is_subsystem;
	ವರ್ಣ	*subsys;
	u_int	ಅಂಕೆ_env;
	ಸಂರಚನಾ {
		ವರ್ಣ	*name;
		ವರ್ಣ	*val;
	} *env;
};

ಶೂನ್ಯ	 do_authenticated(ಸಂರಚನಾ ssh *, Authctxt *);
ಶೂನ್ಯ	 do_cleanup(ಸಂರಚನಾ ssh *, Authctxt *);

ಪೂರ್ಣಾಙ್ಕ	 session_open(Authctxt *, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 session_unused(ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 session_ಒಳಹರಿವು_channel_req(ಸಂರಚನಾ ssh *, Channel *, ಧ್ರುವ ವರ್ಣ *);
ಶೂನ್ಯ	 session_close_by_pid(ಸಂರಚನಾ ssh *ssh, pid_t, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 session_close_by_channel(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಶೂನ್ಯ *);
ಶೂನ್ಯ	 session_destroy_all(ಸಂರಚನಾ ssh *, ಶೂನ್ಯ (*)(Session *));
ಶೂನ್ಯ	 session_pty_cleanup2(Session *);

Session	*session_new(ಶೂನ್ಯ);
Session	*session_by_tty(ವರ್ಣ *);
ಶೂನ್ಯ	 session_close(ಸಂರಚನಾ ssh *, Session *);
ಶೂನ್ಯ	 do_setusercontext(ಸಂರಚನಾ passwd *);

ಧ್ರುವ ವರ್ಣ	*session_get_remote_name_or_ip(ಸಂರಚನಾ ssh *, u_int, ಪೂರ್ಣಾಙ್ಕ);

#endif
