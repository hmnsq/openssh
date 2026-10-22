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

ساختار termios *get_saved_tio(تهی);
تهی	 leave_raw_mode(صحیح);
تهی	 enter_raw_mode(صحیح);

صحیح	 pty_allocate(صحیح *, صحیح *, نویسه *, size_t);
تهی	 pty_release(ثابت نویسه *);
تهی	 pty_make_controlling_tty(صحیح *, ثابت نویسه *);
تهی	 pty_change_window_size(صحیح, u_int, u_int, u_int, u_int);
تهی	 pty_setowner(ساختار passwd *, ثابت نویسه *);
