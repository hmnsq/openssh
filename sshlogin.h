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

શૂન્ય	record_login(pid_t, અચલ અક્ષર *, અચલ અક્ષર *, uid_t,
    અચલ અક્ષર *, સંરચના sockaddr *, socklen_t);
શૂન્ય   record_logout(pid_t, અચલ અક્ષર *, અચલ અક્ષર *);
time_t	get_last_login_time(uid_t, અચલ અક્ષર *, અક્ષર *, size_t);

#ifdef LOGIN_NEEDS_UTMPX
શૂન્ય	record_utmp_only(pid_t, અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *,
		સંરચના sockaddr *, socklen_t);
#endif
