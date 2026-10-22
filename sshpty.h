/* $OpenBSD: sshpty.h,v 1.14 2026/09/15 06:47:42 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for allocating a pseudo-terminal and making it the controlling
 * tty.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#شامل <termios.h>

ساخت termios *get_saved_tio(خالی);
خالی	 leave_raw_منوال(صحیح);
خالی	 enter_raw_منوال(صحیح);

صحیح	 pty_allocate(صحیح *, صحیح *, حرف *, سائز_t);
خالی	 pty_release(ثابت حرف *);
خالی	 pty_make_controlling_tty(صحیح *, ثابت حرف *);
خالی	 pty_change_کھڑکی_سائز(صحیح, u_int, u_int, u_int, u_int);
خالی	 pty_setowner(ساخت passwd *, ثابت حرف *);
