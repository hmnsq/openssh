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

#ಅನ್ತರ್ಭಾವ <termios.h>

ಸಂರಚನಾ termios *get_saved_tio(ಶೂನ್ಯ);
ಶೂನ್ಯ	 leave_raw_mode(ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 enter_raw_mode(ಪೂರ್ಣಾಙ್ಕ);

ಪೂರ್ಣಾಙ್ಕ	 pty_allocate(ಪೂರ್ಣಾಙ್ಕ *, ಪೂರ್ಣಾಙ್ಕ *, ವರ್ಣ *, size_t);
ಶೂನ್ಯ	 pty_release(ಧ್ರುವ ವರ್ಣ *);
ಶೂನ್ಯ	 pty_make_controlling_tty(ಪೂರ್ಣಾಙ್ಕ *, ಧ್ರುವ ವರ್ಣ *);
ಶೂನ್ಯ	 pty_change_window_size(ಪೂರ್ಣಾಙ್ಕ, u_int, u_int, u_int, u_int);
ಶೂನ್ಯ	 pty_setowner(ಸಂರಚನಾ passwd *, ಧ್ರುವ ವರ್ಣ *);
