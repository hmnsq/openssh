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

ശൂന്യം	record_login(pid_t, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, uid_t,
    സ്ഥിരം അക്ഷരം *, ഘടന sockaddr *, socklen_t);
ശൂന്യം   record_logout(pid_t, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
time_t	get_last_login_time(uid_t, സ്ഥിരം അക്ഷരം *, അക്ഷരം *, size_t);

#ifdef LOGIN_NEEDS_UTMPX
ശൂന്യം	record_utmp_only(pid_t, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *,
		ഘടന sockaddr *, socklen_t);
#endif
