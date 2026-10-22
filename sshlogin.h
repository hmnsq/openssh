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

शून्य	record_login(pid_t, ध्रुव वर्ण *, ध्रुव वर्ण *, uid_t,
    ध्रुव वर्ण *, संरचना sockaddr *, socklen_t);
शून्य   record_logout(pid_t, ध्रुव वर्ण *, ध्रुव वर्ण *);
time_t	get_last_login_time(uid_t, ध्रुव वर्ण *, वर्ण *, size_t);

#ifdef LOGIN_NEEDS_UTMPX
शून्य	record_utmp_only(pid_t, ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *,
		संरचना sockaddr *, socklen_t);
#endif
