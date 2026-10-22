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
تعریفنوع ساختار Session Session;
ساختار Session {
	صحیح	used;
	صحیح	self;
	صحیح	next_unused;
	ساختار passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	صحیح	forced;

	/* tty */
	نویسه	*term;
	صحیح	ptyfd, ttyfd, ptymaster;
	u_int	row, col, xpixel, ypixel;
	نویسه	tty[TTYSZ];

	/* X11 */
	u_int	display_عدد;
	نویسه	*display;
	u_int	screen;
	نویسه	*auth_display;
	نویسه	*auth_proto;
	نویسه	*auth_data;
	صحیح	single_connection;

	صحیح	chanid;
	صحیح	*x11_chanids;
	صحیح	is_subsystem;
	نویسه	*subsys;
	u_int	رقم_env;
	ساختار {
		نویسه	*name;
		نویسه	*val;
	} *env;
};

تهی	 do_authenticated(ساختار ssh *, Authctxt *);
تهی	 do_cleanup(ساختار ssh *, Authctxt *);

صحیح	 session_open(Authctxt *, صحیح);
تهی	 session_unused(صحیح);
صحیح	 session_درون_داد_channel_req(ساختار ssh *, Channel *, ثابت نویسه *);
تهی	 session_close_by_pid(ساختار ssh *ssh, pid_t, صحیح);
تهی	 session_close_by_channel(ساختار ssh *, صحیح, صحیح, تهی *);
تهی	 session_destroy_all(ساختار ssh *, تهی (*)(Session *));
تهی	 session_pty_cleanup2(Session *);

Session	*session_new(تهی);
Session	*session_by_tty(نویسه *);
تهی	 session_close(ساختار ssh *, Session *);
تهی	 do_setusercontext(ساختار passwd *);

ثابت نویسه	*session_get_remote_name_or_ip(ساختار ssh *, u_int, صحیح);

#endif
