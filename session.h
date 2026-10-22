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
வகைவரை கட்டமைப்பு Session Session;
கட்டமைப்பு Session {
	முழு	used;
	முழு	self;
	முழு	next_unused;
	கட்டமைப்பு passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	முழு	forced;

	/* tty */
	எழுத்து	*term;
	முழு	ptyfd, ttyfd, ptymaster;
	u_int	row, col, xpixel, ypixel;
	எழுத்து	tty[TTYSZ];

	/* X11 */
	u_int	display_எண்;
	எழுத்து	*display;
	u_int	screen;
	எழுத்து	*auth_display;
	எழுத்து	*auth_proto;
	எழுத்து	*auth_data;
	முழு	single_connection;

	முழு	chanid;
	முழு	*x11_chanids;
	முழு	is_subsystem;
	எழுத்து	*subsys;
	u_int	இலக்கம்_env;
	கட்டமைப்பு {
		எழுத்து	*name;
		எழுத்து	*val;
	} *env;
};

வெறுமை	 do_authenticated(கட்டமைப்பு ssh *, Authctxt *);
வெறுமை	 do_cleanup(கட்டமைப்பு ssh *, Authctxt *);

முழு	 session_open(Authctxt *, முழு);
வெறுமை	 session_unused(முழு);
முழு	 session_உள்ளீடு_channel_req(கட்டமைப்பு ssh *, Channel *, மாறிலி எழுத்து *);
வெறுமை	 session_close_by_pid(கட்டமைப்பு ssh *ssh, pid_t, முழு);
வெறுமை	 session_close_by_channel(கட்டமைப்பு ssh *, முழு, முழு, வெறுமை *);
வெறுமை	 session_destroy_all(கட்டமைப்பு ssh *, வெறுமை (*)(Session *));
வெறுமை	 session_pty_cleanup2(Session *);

Session	*session_new(வெறுமை);
Session	*session_by_tty(எழுத்து *);
வெறுமை	 session_close(கட்டமைப்பு ssh *, Session *);
வெறுமை	 do_setusercontext(கட்டமைப்பு passwd *);

மாறிலி எழுத்து	*session_get_remote_name_or_ip(கட்டமைப்பு ssh *, u_int, முழு);

#endif
