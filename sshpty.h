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

#അന്തര്ഭാവ <termios.h>

ഘടന termios *get_saved_tio(ശൂന്യം);
ശൂന്യം	 leave_raw_mode(പൂർണ്ണസംഖ്യ);
ശൂന്യം	 enter_raw_mode(പൂർണ്ണസംഖ്യ);

പൂർണ്ണസംഖ്യ	 pty_allocate(പൂർണ്ണസംഖ്യ *, പൂർണ്ണസംഖ്യ *, അക്ഷരം *, size_t);
ശൂന്യം	 pty_release(സ്ഥിരം അക്ഷരം *);
ശൂന്യം	 pty_make_controlling_tty(പൂർണ്ണസംഖ്യ *, സ്ഥിരം അക്ഷരം *);
ശൂന്യം	 pty_change_window_size(പൂർണ്ണസംഖ്യ, u_int, u_int, u_int, u_int);
ശൂന്യം	 pty_setowner(ഘടന passwd *, സ്ഥിരം അക്ഷരം *);
