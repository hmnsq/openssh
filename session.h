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
প্রকারলেখ কাঠামো Session Session;
কাঠামো Session {
	পূর্ণসংখ্যা	used;
	পূর্ণসংখ্যা	self;
	পূর্ণসংখ্যা	পরবর্তী_unused;
	কাঠামো passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	পূর্ণসংখ্যা	forced;

	/* tty */
	অক্ষর	*term;
	পূর্ণসংখ্যা	ptyfd, ttyfd, ptymaster;
	u_int	row, col, xpixel, ypixel;
	অক্ষর	tty[TTYSZ];

	/* X11 */
	u_int	display_সংখ্যা;
	অক্ষর	*display;
	u_int	screen;
	অক্ষর	*auth_display;
	অক্ষর	*auth_proto;
	অক্ষর	*auth_তথ্য;
	পূর্ণসংখ্যা	single_connection;

	পূর্ণসংখ্যা	chanid;
	পূর্ণসংখ্যা	*x11_chanids;
	পূর্ণসংখ্যা	is_subsystem;
	অক্ষর	*subsys;
	u_int	অঙ্ক_env;
	কাঠামো {
		অক্ষর	*name;
		অক্ষর	*val;
	} *env;
};

শূন্য	 do_authenticated(কাঠামো ssh *, Authctxt *);
শূন্য	 do_cleanup(কাঠামো ssh *, Authctxt *);

পূর্ণসংখ্যা	 session_open(Authctxt *, পূর্ণসংখ্যা);
শূন্য	 session_unused(পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 session_প্রবেশ_channel_req(কাঠামো ssh *, Channel *, ধ্রুবক অক্ষর *);
শূন্য	 session_close_by_pid(কাঠামো ssh *ssh, pid_t, পূর্ণসংখ্যা);
শূন্য	 session_close_by_channel(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা, শূন্য *);
শূন্য	 session_destroy_all(কাঠামো ssh *, শূন্য (*)(Session *));
শূন্য	 session_pty_cleanup2(Session *);

Session	*session_new(শূন্য);
Session	*session_by_tty(অক্ষর *);
শূন্য	 session_close(কাঠামো ssh *, Session *);
শূন্য	 do_setusercontext(কাঠামো passwd *);

ধ্রুবক অক্ষর	*session_get_remote_name_or_ip(কাঠামো ssh *, u_int, পূর্ণসংখ্যা);

#endif
