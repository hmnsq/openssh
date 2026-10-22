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

#ଅନ୍ତର୍ଭାଵ <termios.h>

ସଂରଚନା termios *get_saved_tio(ଶୂନ୍ୟ);
ଶୂନ୍ୟ	 leave_raw_mode(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 enter_raw_mode(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 pty_allocate(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ଅକ୍ଷର *, size_t);
ଶୂନ୍ୟ	 pty_release(ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ	 pty_make_controlling_tty(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ	 pty_change_window_size(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, u_int, u_int, u_int, u_int);
ଶୂନ୍ୟ	 pty_setowner(ସଂରଚନା passwd *, ଅଚଳ ଅକ୍ଷର *);
