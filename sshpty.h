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

#समावेश <termios.h>

काष्ठा termios *get_saved_tio(व्योम);
व्योम	 leave_raw_mode(पूर्णांक);
व्योम	 enter_raw_mode(पूर्णांक);

पूर्णांक	 pty_allocate(पूर्णांक *, पूर्णांक *, अक्षर *, माप_प्रकार);
व्योम	 pty_release(स्थिर अक्षर *);
व्योम	 pty_make_controlling_tty(पूर्णांक *, स्थिर अक्षर *);
व्योम	 pty_change_window_आकार(पूर्णांक, u_int, u_int, u_int, u_int);
व्योम	 pty_setowner(काष्ठा passwd *, स्थिर अक्षर *);
