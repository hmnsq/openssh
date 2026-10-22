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
#جيڪڏهن_وصف_نه_ٿيل SESSION_H
#وصف_ڪريو SESSION_H

#وصف_ڪريو TTYSZ 64
تعريفنوع بنية Session Session;
بنية Session {
	صحيح	استعمال_ٿيل;
	صحيح	self;
	صحيح	ايندڙ_اڻ_استعمال_ٿيل;
	بنية passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	صحيح	forced;

	/* tty */
	حرف	*رڪن;
	صحيح	ptyfd, ttyfd, ptymaster;
	u_int	صف, کانو, xpixel, ypixel;
	حرف	tty[TTYSZ];

	/* X11 */
	u_int	display_عدد;
	حرف	*display;
	u_int	screen;
	حرف	*auth_display;
	حرف	*auth_proto;
	حرف	*auth_معلومات;
	صحيح	single_connection;

	صحيح	chanid;
	صحيح	*x11_chanids;
	صحيح	is_subsystem;
	حرف	*subsys;
	u_int	انگ_env;
	بنية {
		حرف	*name;
		حرف	*val;
	} *env;
};

فراغ	 do_authenticated(بنية ssh *, Authctxt *);
فراغ	 do_cleanup(بنية ssh *, Authctxt *);

صحيح	 session_open(Authctxt *, صحيح);
فراغ	 session_اڻ_استعمال_ٿيل(صحيح);
صحيح	 session_داخلا_channel_req(بنية ssh *, Channel *, ثابت حرف *);
فراغ	 session_close_by_pid(بنية ssh *ssh, pid_t, صحيح);
فراغ	 session_close_by_channel(بنية ssh *, صحيح, صحيح, فراغ *);
فراغ	 session_destroy_all(بنية ssh *, فراغ (*)(Session *));
فراغ	 session_pty_cleanup2(Session *);

Session	*session_new(فراغ);
Session	*session_by_tty(حرف *);
فراغ	 session_close(بنية ssh *, Session *);
فراغ	 do_setusercontext(بنية passwd *);

ثابت حرف	*session_get_remote_name_or_ip(بنية ssh *, u_int, صحيح);

#جيڪڏهن_پورو
