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

व्योम	record_login(pid_t, स्थिर अक्षर *, स्थिर अक्षर *, uid_t,
    स्थिर अक्षर *, काष्ठा sockaddr *, socklen_t);
व्योम   record_logout(pid_t, स्थिर अक्षर *, स्थिर अक्षर *);
समय_प्रकार	get_last_login_time(uid_t, स्थिर अक्षर *, अक्षर *, माप_प्रकार);

#अगर_घोषित LOGIN_NEEDS_UTMPX
व्योम	record_utmp_only(pid_t, स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *,
		काष्ठा sockaddr *, socklen_t);
#पूर्ण_अगर
