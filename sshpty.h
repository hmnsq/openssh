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

ರಚನೆ termios *get_saved_tio(ಶೂನ್ಯ);
ಶೂನ್ಯ	 leave_raw_ಬಹುಲಕ(ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 enter_raw_ಬಹುಲಕ(ಪೂರ್ಣಾಂಕ);

ಪೂರ್ಣಾಂಕ	 pty_allocate(ಪೂರ್ಣಾಂಕ *, ಪೂರ್ಣಾಂಕ *, ಅಕ್ಷರ *, ಗಾತ್ರ_t);
ಶೂನ್ಯ	 pty_release(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	 pty_make_controlling_tty(ಪೂರ್ಣಾಂಕ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	 pty_change_ಕಿಟಕಿ_ಗಾತ್ರ(ಪೂರ್ಣಾಂಕ, u_int, u_int, u_int, u_int);
ಶೂನ್ಯ	 pty_setowner(ರಚನೆ passwd *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
