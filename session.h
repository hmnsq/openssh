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
#اگر_غیر_تعریف_شدہ SESSION_H
#تعریف_کرو SESSION_H

#تعریف_کرو TTYSZ 64
قسمتعریف ساخت Session Session;
ساخت Session {
	صحیح	مستعمل;
	صحیح	self;
	صحیح	اگلا_غیر_مستعمل;
	ساخت passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	صحیح	forced;

	/* tty */
	حرف	*رکن;
	صحیح	ptyfd, ttyfd, ptymaster;
	u_int	صف, ستون, xpixel, ypixel;
	حرف	tty[TTYSZ];

	/* X11 */
	u_int	display_نمبر;
	حرف	*display;
	u_int	screen;
	حرف	*auth_display;
	حرف	*auth_proto;
	حرف	*auth_ڈیٹا;
	صحیح	single_connection;

	صحیح	chanid;
	صحیح	*x11_chanids;
	صحیح	is_subsystem;
	حرف	*subsys;
	u_int	عدد_env;
	ساخت {
		حرف	*name;
		حرف	*val;
	} *env;
};

خالی	 do_authenticated(ساخت ssh *, Authctxt *);
خالی	 do_cleanup(ساخت ssh *, Authctxt *);

صحیح	 session_open(Authctxt *, صحیح);
خالی	 session_غیر_مستعمل(صحیح);
صحیح	 session_داخلہ_channel_req(ساخت ssh *, Channel *, ثابت حرف *);
خالی	 session_close_by_pid(ساخت ssh *ssh, pid_t, صحیح);
خالی	 session_close_by_channel(ساخت ssh *, صحیح, صحیح, خالی *);
خالی	 session_destroy_all(ساخت ssh *, خالی (*)(Session *));
خالی	 session_pty_cleanup2(Session *);

Session	*session_new(خالی);
Session	*session_by_tty(حرف *);
خالی	 session_close(ساخت ssh *, Session *);
خالی	 do_setusercontext(ساخت passwd *);

ثابت حرف	*session_get_remote_name_or_ip(ساخت ssh *, u_int, صحیح);

#اگر_ختم
