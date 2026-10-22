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

#অন্তর্ভাব <termios.h>

কাঠামো termios *get_saved_tio(শূন্য);
শূন্য	 leave_raw_mode(পূর্ণসংখ্যা);
শূন্য	 enter_raw_mode(পূর্ণসংখ্যা);

পূর্ণসংখ্যা	 pty_allocate(পূর্ণসংখ্যা *, পূর্ণসংখ্যা *, অক্ষর *, আকার_t);
শূন্য	 pty_release(ধ্রুবক অক্ষর *);
শূন্য	 pty_make_controlling_tty(পূর্ণসংখ্যা *, ধ্রুবক অক্ষর *);
শূন্য	 pty_change_window_আকার(পূর্ণসংখ্যা, u_int, u_int, u_int, u_int);
শূন্য	 pty_setowner(কাঠামো passwd *, ধ্রুবক অক্ষর *);
