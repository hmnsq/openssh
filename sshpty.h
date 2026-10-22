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

#ضمن <termios.h>

بنية termios *get_saved_tio(فراغ);
فراغ	 leave_raw_منوال(صحيح);
فراغ	 enter_raw_منوال(صحيح);

صحيح	 pty_allocate(صحيح *, صحيح *, حرف *, ناپ_t);
فراغ	 pty_release(ثابت حرف *);
فراغ	 pty_make_controlling_tty(صحيح *, ثابت حرف *);
فراغ	 pty_change_کھڑکی_ناپ(صحيح, u_int, u_int, u_int, u_int);
فراغ	 pty_setowner(بنية passwd *, ثابت حرف *);
