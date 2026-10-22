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
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SESSION_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SESSION_H

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TTYSZ 64
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ Session Session;
ਬਣਤਰ Session {
	ਪੂਰਨ	ਵਰਤਿਆ;
	ਪੂਰਨ	self;
	ਪੂਰਨ	ਅਗਲਾ_ਅਣਵਰਤਿਆ;
	ਬਣਤਰ passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	ਪੂਰਨ	forced;

	/* tty */
	ਅੱਖਰ	*ਪਦ;
	ਪੂਰਨ	ptyfd, ttyfd, ptymaster;
	u_int	ਪੰਕਤੀ, ਖਾਨਾ, xpixel, ypixel;
	ਅੱਖਰ	tty[TTYSZ];

	/* X11 */
	u_int	display_ਸੰਖਿਆ;
	ਅੱਖਰ	*display;
	u_int	screen;
	ਅੱਖਰ	*auth_display;
	ਅੱਖਰ	*auth_proto;
	ਅੱਖਰ	*auth_ਅੰਕੜੇ;
	ਪੂਰਨ	single_connection;

	ਪੂਰਨ	chanid;
	ਪੂਰਨ	*x11_chanids;
	ਪੂਰਨ	is_subsystem;
	ਅੱਖਰ	*subsys;
	u_int	ਅੰਕ_env;
	ਬਣਤਰ {
		ਅੱਖਰ	*name;
		ਅੱਖਰ	*val;
	} *env;
};

ਖਾਲੀ	 do_authenticated(ਬਣਤਰ ssh *, Authctxt *);
ਖਾਲੀ	 do_cleanup(ਬਣਤਰ ssh *, Authctxt *);

ਪੂਰਨ	 session_open(Authctxt *, ਪੂਰਨ);
ਖਾਲੀ	 session_ਅਣਵਰਤਿਆ(ਪੂਰਨ);
ਪੂਰਨ	 session_ਨਿਵੇਸ਼_channel_req(ਬਣਤਰ ssh *, Channel *, ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	 session_close_by_pid(ਬਣਤਰ ssh *ssh, pid_t, ਪੂਰਨ);
ਖਾਲੀ	 session_close_by_channel(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ, ਖਾਲੀ *);
ਖਾਲੀ	 session_destroy_all(ਬਣਤਰ ssh *, ਖਾਲੀ (*)(Session *));
ਖਾਲੀ	 session_pty_cleanup2(Session *);

Session	*session_new(ਖਾਲੀ);
Session	*session_by_tty(ਅੱਖਰ *);
ਖਾਲੀ	 session_close(ਬਣਤਰ ssh *, Session *);
ਖਾਲੀ	 do_setusercontext(ਬਣਤਰ passwd *);

ਅਚਲ ਅੱਖਰ	*session_get_remote_name_or_ip(ਬਣਤਰ ssh *, u_int, ਪੂਰਨ);

#ਜੇ_ਅੰਤ
