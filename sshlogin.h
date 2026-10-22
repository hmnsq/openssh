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

ਖਾਲੀ	ਰਿਕਾਰਡ_login(pid_t, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, uid_t,
    ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sockaddr *, socklen_t);
ਖਾਲੀ   ਰਿਕਾਰਡ_logout(pid_t, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
time_t	get_ਆਖਰੀ_login_ਸਮਾਂ(uid_t, ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ *, ਮਾਪ_t);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LOGIN_NEEDS_UTMPX
ਖਾਲੀ	ਰਿਕਾਰਡ_utmp_only(pid_t, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
		ਬਣਤਰ sockaddr *, socklen_t);
#ਜੇ_ਅੰਤ
