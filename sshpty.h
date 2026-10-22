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

#அந்தர்பாவ <termios.h>

கட்டமைப்பு termios *get_saved_tio(வெறுமை);
வெறுமை	 leave_raw_mode(முழு);
வெறுமை	 enter_raw_mode(முழு);

முழு	 pty_allocate(முழு *, முழு *, எழுத்து *, size_t);
வெறுமை	 pty_release(மாறிலி எழுத்து *);
வெறுமை	 pty_make_controlling_tty(முழு *, மாறிலி எழுத்து *);
வெறுமை	 pty_change_window_size(முழு, u_int, u_int, u_int, u_int);
வெறுமை	 pty_setowner(கட்டமைப்பு passwd *, மாறிலி எழுத்து *);
