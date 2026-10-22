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
typedef sa_nracanaa Session Session;
sa_nracanaa Session {
	ຈຳນວນເຕັມ	used;
	ຈຳນວນເຕັມ	self;
	ຈຳນວນເຕັມ	next_unused;
	sa_nracanaa passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	ຈຳນວນເຕັມ	forced;

	/* tty */
	var_na	*term;
	ຈຳນວນເຕັມ	ptyfd, ttyfd, ptymaster;
	u_int	row, col, xpixel, ypixel;
	var_na	tty[TTYSZ];

	/* X11 */
	u_int	display_number;
	var_na	*display;
	u_int	screen;
	var_na	*auth_display;
	var_na	*auth_proto;
	var_na	*auth_data;
	ຈຳນວນເຕັມ	single_connection;

	ຈຳນວນເຕັມ	chanid;
	ຈຳນວນເຕັມ	*x11_chanids;
	ຈຳນວນເຕັມ	is_subsystem;
	var_na	*subsys;
	u_int	num_env;
	sa_nracanaa {
		var_na	*name;
		var_na	*val;
	} *env;
};

void	 do_authenticated(sa_nracanaa ssh *, Authctxt *);
void	 do_cleanup(sa_nracanaa ssh *, Authctxt *);

ຈຳນວນເຕັມ	 session_open(Authctxt *, ຈຳນວນເຕັມ);
void	 session_unused(ຈຳນວນເຕັມ);
ຈຳນວນເຕັມ	 session_input_channel_req(sa_nracanaa ssh *, Channel *, const var_na *);
void	 session_close_by_pid(sa_nracanaa ssh *ssh, pid_t, ຈຳນວນເຕັມ);
void	 session_close_by_channel(sa_nracanaa ssh *, ຈຳນວນເຕັມ, ຈຳນວນເຕັມ, void *);
void	 session_destroy_all(sa_nracanaa ssh *, void (*)(Session *));
void	 session_pty_cleanup2(Session *);

Session	*session_new(void);
Session	*session_by_tty(var_na *);
void	 session_close(sa_nracanaa ssh *, Session *);
void	 do_setusercontext(sa_nracanaa passwd *);

const var_na	*session_get_remote_name_or_ip(sa_nracanaa ssh *, u_int, ຈຳນວນເຕັມ);

#endif
