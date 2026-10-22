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

فراغ	ریکارڈ_login(pid_t, ثابت حرف *, ثابت حرف *, uid_t,
    ثابت حرف *, بنية sockaddr *, socklen_t);
فراغ   ریکارڈ_logout(pid_t, ثابت حرف *, ثابت حرف *);
time_t	get_آخری_login_ویلا(uid_t, ثابت حرف *, حرف *, ناپ_t);

#جے_تعریف_شدہ LOGIN_NEEDS_UTMPX
فراغ	ریکارڈ_utmp_only(pid_t, ثابت حرف *, ثابت حرف *, ثابت حرف *,
		بنية sockaddr *, socklen_t);
#جے_انت
