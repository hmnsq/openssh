/* $OpenBSD: sshlogin.c,v 1.37 2026/02/16 23:47:06 jsg Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file performs some of the things login(1) normally does.  We cannot
 * easily use something like login -p -h host -f user, because there are
 * several different logins around, and it is hard to determined what kind of
 * login the current system has.  Also, we want to be able to execute commands
 * on a tty.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 1999 Theo de Raadt.  All rights reserved.
 * Copyright (c) 1999 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ಅನ್ತರ್ಭಾವ "sshlogin.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "loginrec.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"

ಬಾಹ್ಯ ರಚನೆ sshbuf *loginmsg;
ಬಾಹ್ಯ ServerOptions options;

/*
 * Returns the time when the user last logged in.  Returns 0 if the
 * information is not available.  This must be called before record_login.
 * The host the user logged in from will be returned in buf.
 */
time_t
get_ಕೊನೆಯ_login_ಸಮಯ(uid_t uid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *logname,
    ಅಕ್ಷರ *buf, ಗಾತ್ರ_t bufsize)
{
	ರಚನೆ logininfo li;

	login_get_lastlog(&li, uid);
	strlcpy(buf, li.hostname, bufsize);
	ಹಿಂತಿರುಗಿ (time_t)li.tv_sec;
}

/*
 * Generate and store last login message.  This must be done before
 * login_login() is called and lastlog is updated.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
store_lastlog_ಸಂದೇಶ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, uid_t uid)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ NO_SSH_LASTLOG
# ifndef CUSTOM_SYS_AUTH_GET_LASTLOGIN_ಸಂದೇಶ
	ಅಕ್ಷರ hostname[HOST_NAME_MAX+1] = "";
	time_t ಕೊನೆಯ_login_ಸಮಯ;
# endif
	ಅಕ್ಷರ *ಸಮಯ_string;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (!options.print_lastlog)
		ಹಿಂತಿರುಗಿ;

# ifdef CUSTOM_SYS_AUTH_GET_LASTLOGIN_ಸಂದೇಶ
	ಸಮಯ_string = sys_auth_get_lastlogin_ಸಂದೇಶ(user, uid);
	ಆದರೆ (ಸಮಯ_string != ಖಾಲಿ) {
		ಆದರೆ ((r = sshbuf_put(loginmsg,
		    ಸಮಯ_string, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಸಮಯ_string))) != 0)
			fatal_fr(r, "buffer error");
		ಬಿಡುಗಡೆ(ಸಮಯ_string);
	}
# ಇಲ್ಲದಿದ್ದರೆ
	ಕೊನೆಯ_login_ಸಮಯ = get_ಕೊನೆಯ_login_ಸಮಯ(uid, user, hostname,
	    ಗಾತ್ರ(hostname));

	ಆದರೆ (ಕೊನೆಯ_login_ಸಮಯ != 0) {
		ಸಮಯ_string = ctime(&ಕೊನೆಯ_login_ಸಮಯ);
		ಸಮಯ_string[strcspn(ಸಮಯ_string, "\n")] = '\0';
		ಆದರೆ (strcmp(hostname, "") == 0)
			r = sshbuf_putf(loginmsg, "Last login: %s\r\n",
			    ಸಮಯ_string);
		ಇಲ್ಲದಿದ್ದರೆ
			r = sshbuf_putf(loginmsg, "Last login: %s from %s\r\n",
			    ಸಮಯ_string, hostname);
		ಆದರೆ (r != 0)
			fatal_fr(r, "sshbuf_putf");
	}
# endif /* CUSTOM_SYS_AUTH_GET_LASTLOGIN_MSG */
#ಆದರೆ_ಅಂತ್ಯ /* NO_SSH_LASTLOG */
}

/*
 * Records that the user has logged in.  I wish these parts of operating
 * systems were more standardized.
 */
ಶೂನ್ಯ
ದಾಖಲೆ_login(pid_t pid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *tty, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, uid_t uid,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ರಚನೆ sockaddr *addr, socklen_t addrlen)
{
	ರಚನೆ logininfo *li;

	/* save previous login details before writing new */
	store_lastlog_ಸಂದೇಶ(user, uid);

	li = login_alloc_ನಮೂದು(pid, user, host, tty);
	login_ಗಣ_addr(li, addr, addrlen);
	login_login(li);
	login_free_ನಮೂದು(li);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LOGIN_NEEDS_UTMPX
ಶೂನ್ಯ
ದಾಖಲೆ_utmp_only(pid_t pid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ttyname, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user,
		 ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ರಚನೆ sockaddr *addr, socklen_t addrlen)
{
	ರಚನೆ logininfo *li;

	li = login_alloc_ನಮೂದು(pid, user, host, ttyname);
	login_ಗಣ_addr(li, addr, addrlen);
	login_utmp_only(li);
	login_free_ನಮೂದು(li);
}
#ಆದರೆ_ಅಂತ್ಯ

/* Records that the user has logged out. */
ಶೂನ್ಯ
ದಾಖಲೆ_logout(pid_t pid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *tty, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user)
{
	ರಚನೆ logininfo *li;

	li = login_alloc_ನಮೂದು(pid, user, ಖಾಲಿ, tty);
	login_logout(li);
	login_free_ನಮೂದು(li);
}
