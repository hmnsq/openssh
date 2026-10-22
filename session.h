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
തരനിർവചനം ഘടന Session Session;
ഘടന Session {
	പൂർണ്ണസംഖ്യ	used;
	പൂർണ്ണസംഖ്യ	self;
	പൂർണ്ണസംഖ്യ	next_unused;
	ഘടന passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	പൂർണ്ണസംഖ്യ	forced;

	/* tty */
	അക്ഷരം	*term;
	പൂർണ്ണസംഖ്യ	ptyfd, ttyfd, ptymaster;
	u_int	row, col, xpixel, ypixel;
	അക്ഷരം	tty[TTYSZ];

	/* X11 */
	u_int	display_സംഖ്യ;
	അക്ഷരം	*display;
	u_int	screen;
	അക്ഷരം	*auth_display;
	അക്ഷരം	*auth_proto;
	അക്ഷരം	*auth_data;
	പൂർണ്ണസംഖ്യ	single_connection;

	പൂർണ്ണസംഖ്യ	chanid;
	പൂർണ്ണസംഖ്യ	*x11_chanids;
	പൂർണ്ണസംഖ്യ	is_subsystem;
	അക്ഷരം	*subsys;
	u_int	അക്കം_env;
	ഘടന {
		അക്ഷരം	*name;
		അക്ഷരം	*val;
	} *env;
};

ശൂന്യം	 do_authenticated(ഘടന ssh *, Authctxt *);
ശൂന്യം	 do_cleanup(ഘടന ssh *, Authctxt *);

പൂർണ്ണസംഖ്യ	 session_open(Authctxt *, പൂർണ്ണസംഖ്യ);
ശൂന്യം	 session_unused(പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 session_നിവേശം_channel_req(ഘടന ssh *, Channel *, സ്ഥിരം അക്ഷരം *);
ശൂന്യം	 session_close_by_pid(ഘടന ssh *ssh, pid_t, പൂർണ്ണസംഖ്യ);
ശൂന്യം	 session_close_by_channel(ഘടന ssh *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, ശൂന്യം *);
ശൂന്യം	 session_destroy_all(ഘടന ssh *, ശൂന്യം (*)(Session *));
ശൂന്യം	 session_pty_cleanup2(Session *);

Session	*session_new(ശൂന്യം);
Session	*session_by_tty(അക്ഷരം *);
ശൂന്യം	 session_close(ഘടന ssh *, Session *);
ശൂന്യം	 do_setusercontext(ഘടന passwd *);

സ്ഥിരം അക്ഷരം	*session_get_remote_name_or_ip(ഘടന ssh *, u_int, പൂർണ്ണസംഖ്യ);

#endif
