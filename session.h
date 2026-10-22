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
प्रकारव्याख्या संरचना Session Session;
संरचना Session {
	पूर्णांक	used;
	पूर्णांक	self;
	पूर्णांक	next_unused;
	संरचना passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	पूर्णांक	forced;

	/* tty */
	अक्षर	*term;
	पूर्णांक	ptyfd, ttyfd, ptymaster;
	u_int	row, col, xpixel, ypixel;
	अक्षर	tty[TTYSZ];

	/* X11 */
	u_int	display_संख्या;
	अक्षर	*display;
	u_int	screen;
	अक्षर	*auth_display;
	अक्षर	*auth_proto;
	अक्षर	*auth_data;
	पूर्णांक	single_connection;

	पूर्णांक	chanid;
	पूर्णांक	*x11_chanids;
	पूर्णांक	is_subsystem;
	अक्षर	*subsys;
	u_int	अंक_env;
	संरचना {
		अक्षर	*name;
		अक्षर	*val;
	} *env;
};

शून्य	 do_authenticated(संरचना ssh *, Authctxt *);
शून्य	 do_cleanup(संरचना ssh *, Authctxt *);

पूर्णांक	 session_open(Authctxt *, पूर्णांक);
शून्य	 session_unused(पूर्णांक);
पूर्णांक	 session_आदान_channel_req(संरचना ssh *, Channel *, स्थिरांक अक्षर *);
शून्य	 session_close_by_pid(संरचना ssh *ssh, pid_t, पूर्णांक);
शून्य	 session_close_by_channel(संरचना ssh *, पूर्णांक, पूर्णांक, शून्य *);
शून्य	 session_destroy_all(संरचना ssh *, शून्य (*)(Session *));
शून्य	 session_pty_cleanup2(Session *);

Session	*session_new(शून्य);
Session	*session_by_tty(अक्षर *);
शून्य	 session_close(संरचना ssh *, Session *);
शून्य	 do_setusercontext(संरचना passwd *);

स्थिरांक अक्षर	*session_get_remote_name_or_ip(संरचना ssh *, u_int, पूर्णांक);

#endif
