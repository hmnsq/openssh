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

#అన్తర్భావ <termios.h>

నిర్మాణం termios *get_saved_tio(శూన్య);
శూన్య	 leave_raw_బహుళకం(పూర్ణాంకం);
శూన్య	 enter_raw_బహుళకం(పూర్ణాంకం);

పూర్ణాంకం	 pty_allocate(పూర్ణాంకం *, పూర్ణాంకం *, అక్షరం *, కొలత_t);
శూన్య	 pty_release(స్థిరరాశి అక్షరం *);
శూన్య	 pty_make_controlling_tty(పూర్ణాంకం *, స్థిరరాశి అక్షరం *);
శూన్య	 pty_change_కిటికీ_కొలత(పూర్ణాంకం, u_int, u_int, u_int, u_int);
శూన్య	 pty_setowner(నిర్మాణం passwd *, స్థిరరాశి అక్షరం *);
