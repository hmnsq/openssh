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
প্রকারনির্দেশ সংরচনা Session Session;
সংরচনা Session {
	পূর্ণাঙ্ক	used;
	পূর্ণাঙ্ক	self;
	পূর্ণাঙ্ক	next_unused;
	সংরচনা passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	পূর্ণাঙ্ক	forced;

	/* tty */
	বর্ণ	*term;
	পূর্ণাঙ্ক	ptyfd, ttyfd, ptymaster;
	u_int	row, col, xpixel, ypixel;
	বর্ণ	tty[TTYSZ];

	/* X11 */
	u_int	display_সংখ্যা;
	বর্ণ	*display;
	u_int	screen;
	বর্ণ	*auth_display;
	বর্ণ	*auth_proto;
	বর্ণ	*auth_data;
	পূর্ণাঙ্ক	single_connection;

	পূর্ণাঙ্ক	chanid;
	পূর্ণাঙ্ক	*x11_chanids;
	পূর্ণাঙ্ক	is_subsystem;
	বর্ণ	*subsys;
	u_int	অঙ্ক_env;
	সংরচনা {
		বর্ণ	*name;
		বর্ণ	*val;
	} *env;
};

শূন্য	 do_authenticated(সংরচনা ssh *, Authctxt *);
শূন্য	 do_cleanup(সংরচনা ssh *, Authctxt *);

পূর্ণাঙ্ক	 session_open(Authctxt *, পূর্ণাঙ্ক);
শূন্য	 session_unused(পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 session_প্রবেশ_channel_req(সংরচনা ssh *, Channel *, ধ্রুব বর্ণ *);
শূন্য	 session_close_by_pid(সংরচনা ssh *ssh, pid_t, পূর্ণাঙ্ক);
শূন্য	 session_close_by_channel(সংরচনা ssh *, পূর্ণাঙ্ক, পূর্ণাঙ্ক, শূন্য *);
শূন্য	 session_destroy_all(সংরচনা ssh *, শূন্য (*)(Session *));
শূন্য	 session_pty_cleanup2(Session *);

Session	*session_new(শূন্য);
Session	*session_by_tty(বর্ণ *);
শূন্য	 session_close(সংরচনা ssh *, Session *);
শূন্য	 do_setusercontext(সংরচনা passwd *);

ধ্রুব বর্ণ	*session_get_remote_name_or_ip(সংরচনা ssh *, u_int, পূর্ণাঙ্ক);

#endif
