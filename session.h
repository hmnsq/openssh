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
प्रकारनिर्देश संरचना Session Session;
संरचना Session {
	पूर्णाङ्क	used;
	पूर्णाङ्क	self;
	पूर्णाङ्क	next_unused;
	संरचना passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	पूर्णाङ्क	forced;

	/* tty */
	वर्ण	*term;
	पूर्णाङ्क	ptyfd, ttyfd, ptymaster;
	u_int	row, col, xpixel, ypixel;
	वर्ण	tty[TTYSZ];

	/* X11 */
	u_int	display_सङ्ख्या;
	वर्ण	*display;
	u_int	screen;
	वर्ण	*auth_display;
	वर्ण	*auth_proto;
	वर्ण	*auth_data;
	पूर्णाङ्क	single_connection;

	पूर्णाङ्क	chanid;
	पूर्णाङ्क	*x11_chanids;
	पूर्णाङ्क	is_subsystem;
	वर्ण	*subsys;
	u_int	अङ्क_env;
	संरचना {
		वर्ण	*name;
		वर्ण	*val;
	} *env;
};

शून्य	 do_authenticated(संरचना ssh *, Authctxt *);
शून्य	 do_cleanup(संरचना ssh *, Authctxt *);

पूर्णाङ्क	 session_open(Authctxt *, पूर्णाङ्क);
शून्य	 session_unused(पूर्णाङ्क);
पूर्णाङ्क	 session_आगत_channel_req(संरचना ssh *, Channel *, अचर वर्ण *);
शून्य	 session_close_by_pid(संरचना ssh *ssh, pid_t, पूर्णाङ्क);
शून्य	 session_close_by_channel(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क, शून्य *);
शून्य	 session_destroy_all(संरचना ssh *, शून्य (*)(Session *));
शून्य	 session_pty_cleanup2(Session *);

Session	*session_new(शून्य);
Session	*session_by_tty(वर्ण *);
शून्य	 session_close(संरचना ssh *, Session *);
शून्य	 do_setusercontext(संरचना passwd *);

अचर वर्ण	*session_get_remote_name_or_ip(संरचना ssh *, u_int, पूर्णाङ्क);

#endif
