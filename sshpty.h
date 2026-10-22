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

#અન્તર્ભાવ <termios.h>

સંરચના termios *get_saved_tio(શૂન્ય);
શૂન્ય	 leave_raw_mode(પૂર્ણાંક);
શૂન્ય	 enter_raw_mode(પૂર્ણાંક);

પૂર્ણાંક	 pty_allocate(પૂર્ણાંક *, પૂર્ણાંક *, અક્ષર *, size_t);
શૂન્ય	 pty_release(અચલ અક્ષર *);
શૂન્ય	 pty_make_controlling_tty(પૂર્ણાંક *, અચલ અક્ષર *);
શૂન્ય	 pty_change_window_size(પૂર્ણાંક, u_int, u_int, u_int, u_int);
શૂન્ય	 pty_setowner(સંરચના passwd *, અચલ અક્ષર *);
