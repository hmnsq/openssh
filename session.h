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
પ્રકારવ્યાખ્યા સંરચના Session Session;
સંરચના Session {
	પૂર્ણાંક	used;
	પૂર્ણાંક	self;
	પૂર્ણાંક	next_unused;
	સંરચના passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	પૂર્ણાંક	forced;

	/* tty */
	અક્ષર	*term;
	પૂર્ણાંક	ptyfd, ttyfd, ptymaster;
	u_int	row, col, xpixel, ypixel;
	અક્ષર	tty[TTYSZ];

	/* X11 */
	u_int	display_સંખ્યા;
	અક્ષર	*display;
	u_int	screen;
	અક્ષર	*auth_display;
	અક્ષર	*auth_proto;
	અક્ષર	*auth_data;
	પૂર્ણાંક	single_connection;

	પૂર્ણાંક	chanid;
	પૂર્ણાંક	*x11_chanids;
	પૂર્ણાંક	is_subsystem;
	અક્ષર	*subsys;
	u_int	અંક_env;
	સંરચના {
		અક્ષર	*name;
		અક્ષર	*val;
	} *env;
};

શૂન્ય	 do_authenticated(સંરચના ssh *, Authctxt *);
શૂન્ય	 do_cleanup(સંરચના ssh *, Authctxt *);

પૂર્ણાંક	 session_open(Authctxt *, પૂર્ણાંક);
શૂન્ય	 session_unused(પૂર્ણાંક);
પૂર્ણાંક	 session_આગત_channel_req(સંરચના ssh *, Channel *, અચલ અક્ષર *);
શૂન્ય	 session_close_by_pid(સંરચના ssh *ssh, pid_t, પૂર્ણાંક);
શૂન્ય	 session_close_by_channel(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક, શૂન્ય *);
શૂન્ય	 session_destroy_all(સંરચના ssh *, શૂન્ય (*)(Session *));
શૂન્ય	 session_pty_cleanup2(Session *);

Session	*session_new(શૂન્ય);
Session	*session_by_tty(અક્ષર *);
શૂન્ય	 session_close(સંરચના ssh *, Session *);
શૂન્ય	 do_setusercontext(સંરચના passwd *);

અચલ અક્ષર	*session_get_remote_name_or_ip(સંરચના ssh *, u_int, પૂર્ણાંક);

#endif
