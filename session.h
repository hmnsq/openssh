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
typedef struct Session Session;
struct Session {
	số_nguyên	used;
	số_nguyên	self;
	số_nguyên	next_unused;
	struct passwd *pw;
	Authctxt *authctxt;
	pid_t	pid;
	số_nguyên	forced;

	/* tty */
	char	*term;
	số_nguyên	ptyfd, ttyfd, ptymaster;
	u_int	row, col, xpixel, ypixel;
	char	tty[TTYSZ];

	/* X11 */
	u_int	display_number;
	char	*display;
	u_int	screen;
	char	*auth_display;
	char	*auth_proto;
	char	*auth_data;
	số_nguyên	single_connection;

	số_nguyên	chanid;
	số_nguyên	*x11_chanids;
	số_nguyên	is_subsystem;
	char	*subsys;
	u_int	num_env;
	struct {
		char	*name;
		char	*val;
	} *env;
};

void	 do_authenticated(struct ssh *, Authctxt *);
void	 do_cleanup(struct ssh *, Authctxt *);

số_nguyên	 session_open(Authctxt *, số_nguyên);
void	 session_unused(số_nguyên);
số_nguyên	 session_input_channel_req(struct ssh *, Channel *, const char *);
void	 session_close_by_pid(struct ssh *ssh, pid_t, số_nguyên);
void	 session_close_by_channel(struct ssh *, số_nguyên, số_nguyên, void *);
void	 session_destroy_all(struct ssh *, void (*)(Session *));
void	 session_pty_cleanup2(Session *);

Session	*session_new(void);
Session	*session_by_tty(char *);
void	 session_close(struct ssh *, Session *);
void	 do_setusercontext(struct passwd *);

const char	*session_get_remote_name_or_ip(struct ssh *, u_int, số_nguyên);

#endif
