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

#ਅਨ੍ਤਰ੍ਭਾਵ <termios.h>

ਬਣਤਰ termios *get_saved_tio(ਖਾਲੀ);
ਖਾਲੀ	 leave_raw_ਬਹੁਲਕ(ਪੂਰਨ);
ਖਾਲੀ	 enter_raw_ਬਹੁਲਕ(ਪੂਰਨ);

ਪੂਰਨ	 pty_allocate(ਪੂਰਨ *, ਪੂਰਨ *, ਅੱਖਰ *, ਮਾਪ_t);
ਖਾਲੀ	 pty_release(ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	 pty_make_controlling_tty(ਪੂਰਨ *, ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	 pty_change_ਖਿੜਕੀ_ਮਾਪ(ਪੂਰਨ, u_int, u_int, u_int, u_int);
ਖਾਲੀ	 pty_setowner(ਬਣਤਰ passwd *, ਅਚਲ ਅੱਖਰ *);
