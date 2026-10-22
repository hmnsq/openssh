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

ಶೂನ್ಯ	ದಾಖಲೆ_login(pid_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, uid_t,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sockaddr *, socklen_t);
ಶೂನ್ಯ   ದಾಖಲೆ_logout(pid_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
time_t	get_ಕೊನೆಯ_login_ಸಮಯ(uid_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *, ಗಾತ್ರ_t);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LOGIN_NEEDS_UTMPX
ಶೂನ್ಯ	ದಾಖಲೆ_utmp_only(pid_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
		ರಚನೆ sockaddr *, socklen_t);
#ಆದರೆ_ಅಂತ್ಯ
