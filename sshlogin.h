/* $OpenBSD: sshlogin.h,v 1.8 2006/08/03 03:34:42 deraadt Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

శూన్య	రికార్డు_login(pid_t, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, uid_t,
    స్థిరరాశి అక్షరం *, నిర్మాణం sockaddr *, socklen_t);
శూన్య   రికార్డు_logout(pid_t, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
time_t	get_చివరి_login_సమయం(uid_t, స్థిరరాశి అక్షరం *, అక్షరం *, కొలత_t);

#నిర్వచితమైతే LOGIN_NEEDS_UTMPX
శూన్య	రికార్డు_utmp_only(pid_t, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
		నిర్మాణం sockaddr *, socklen_t);
#అయితే_ముగింపు
