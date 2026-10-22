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
#अगर_अघोषित SESSION_H
#घोषणा SESSION_H

#घोषणा TTYSZ 64
प्रकार काष्ठा Session Session;
काष्ठा Session {
	पूर्णांक	used;
	पूर्णांक	self;
	पूर्णांक	अग्र_unused;
	काष्ठा passwd *pw;
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
	अक्षर	*auth_तथ्य;
	पूर्णांक	single_connection;

	पूर्णांक	chanid;
	पूर्णांक	*x11_chanids;
	पूर्णांक	is_subsystem;
	अक्षर	*subsys;
	u_int	अंक_env;
	काष्ठा {
		अक्षर	*name;
		अक्षर	*val;
	} *env;
};

व्योम	 do_authenticated(काष्ठा ssh *, Authctxt *);
व्योम	 do_cleanup(काष्ठा ssh *, Authctxt *);

पूर्णांक	 session_open(Authctxt *, पूर्णांक);
व्योम	 session_unused(पूर्णांक);
पूर्णांक	 session_निवेश_channel_req(काष्ठा ssh *, Channel *, स्थिर अक्षर *);
व्योम	 session_close_by_pid(काष्ठा ssh *ssh, pid_t, पूर्णांक);
व्योम	 session_close_by_channel(काष्ठा ssh *, पूर्णांक, पूर्णांक, व्योम *);
व्योम	 session_destroy_all(काष्ठा ssh *, व्योम (*)(Session *));
व्योम	 session_pty_cleanup2(Session *);

Session	*session_new(व्योम);
Session	*session_by_tty(अक्षर *);
व्योम	 session_close(काष्ठा ssh *, Session *);
व्योम	 do_setusercontext(काष्ठा passwd *);

स्थिर अक्षर	*session_get_remote_name_or_ip(काष्ठा ssh *, u_int, पूर्णांक);

#पूर्ण_अगर
