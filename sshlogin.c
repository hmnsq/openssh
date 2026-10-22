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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>

#अन्तर्भाव <netinet/in.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव "sshlogin.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "loginrec.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"

बाह्य संरचना sshbuf *loginmsg;
बाह्य ServerOptions options;

/*
 * Returns the time when the user last logged in.  Returns 0 if the
 * information is not available.  This must be called before record_login.
 * The host the user logged in from will be returned in buf.
 */
time_t
get_चरमः_login_time(uid_t uid, ध्रुव वर्ण *logname,
    वर्ण *buf, आकार_t bufsize)
{
	संरचना logininfo li;

	login_get_lastlog(&li, uid);
	strlcpy(buf, li.hostname, bufsize);
	प्रत्यागम (time_t)li.tv_sec;
}

/*
 * Generate and store last login message.  This must be done before
 * login_login() is called and lastlog is updated.
 */
स्थिर शून्य
store_lastlog_सन्देशः(ध्रुव वर्ण *user, uid_t uid)
{
#यदि_अपरिभाषितम् NO_SSH_LASTLOG
# ifndef CUSTOM_SYS_AUTH_GET_LASTLOGIN_सन्देशः
	वर्ण hostname[HOST_NAME_MAX+1] = "";
	time_t चरमः_login_time;
# endif
	वर्ण *time_string;
	पूर्णाङ्क r;

	यदि (!options.print_lastlog)
		प्रत्यागम;

# ifdef CUSTOM_SYS_AUTH_GET_LASTLOGIN_सन्देशः
	time_string = sys_auth_get_lastlogin_सन्देशः(user, uid);
	यदि (time_string != रिक्त) {
		यदि ((r = sshbuf_put(loginmsg,
		    time_string, वाक्यदैर्घ्यम्(time_string))) != 0)
			fatal_fr(r, "buffer error");
		मुक्त(time_string);
	}
# अन्यथा
	चरमः_login_time = get_चरमः_login_time(uid, user, hostname,
	    परिमाण(hostname));

	यदि (चरमः_login_time != 0) {
		time_string = ctime(&चरमः_login_time);
		time_string[strcspn(time_string, "\n")] = '\0';
		यदि (वाक्यं_तुलय(hostname, "") == 0)
			r = sshbuf_putf(loginmsg, "Last login: %s\r\n",
			    time_string);
		अन्यथा
			r = sshbuf_putf(loginmsg, "Last login: %s from %s\r\n",
			    time_string, hostname);
		यदि (r != 0)
			fatal_fr(r, "sshbuf_putf");
	}
# endif /* CUSTOM_SYS_AUTH_GET_LASTLOGIN_MSG */
#यदि_अन्तः /* NO_SSH_LASTLOG */
}

/*
 * Records that the user has logged in.  I wish these parts of operating
 * systems were more standardized.
 */
शून्य
लेखः_login(pid_t pid, ध्रुव वर्ण *tty, ध्रुव वर्ण *user, uid_t uid,
    ध्रुव वर्ण *host, संरचना sockaddr *addr, socklen_t addrlen)
{
	संरचना logininfo *li;

	/* save previous login details before writing new */
	store_lastlog_सन्देशः(user, uid);

	li = login_alloc_प्रविष्टिः(pid, user, host, tty);
	login_समुच्चयः_addr(li, addr, addrlen);
	login_login(li);
	login_free_प्रविष्टिः(li);
}

#यदि_परिभाषितम् LOGIN_NEEDS_UTMPX
शून्य
लेखः_utmp_only(pid_t pid, ध्रुव वर्ण *ttyname, ध्रुव वर्ण *user,
		 ध्रुव वर्ण *host, संरचना sockaddr *addr, socklen_t addrlen)
{
	संरचना logininfo *li;

	li = login_alloc_प्रविष्टिः(pid, user, host, ttyname);
	login_समुच्चयः_addr(li, addr, addrlen);
	login_utmp_only(li);
	login_free_प्रविष्टिः(li);
}
#यदि_अन्तः

/* Records that the user has logged out. */
शून्य
लेखः_logout(pid_t pid, ध्रुव वर्ण *tty, ध्रुव वर्ण *user)
{
	संरचना logininfo *li;

	li = login_alloc_प्रविष्टिः(pid, user, रिक्त, tty);
	login_logout(li);
	login_free_प्रविष्टिः(li);
}
