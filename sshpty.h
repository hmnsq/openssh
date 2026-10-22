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

#अन्तर्भाव <termios.h>

संरचना termios *get_saved_tio(शून्य);
शून्य	 leave_raw_mode(पूर्णाङ्क);
शून्य	 enter_raw_mode(पूर्णाङ्क);

पूर्णाङ्क	 pty_allocate(पूर्णाङ्क *, पूर्णाङ्क *, वर्ण *, माप_प्रकार);
शून्य	 pty_release(अचर वर्ण *);
शून्य	 pty_make_controlling_tty(पूर्णाङ्क *, अचर वर्ण *);
शून्य	 pty_change_window_size(पूर्णाङ्क, u_int, u_int, u_int, u_int);
शून्य	 pty_setowner(संरचना passwd *, अचर वर्ण *);
