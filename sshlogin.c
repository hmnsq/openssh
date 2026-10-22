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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/socket.h>

#समावेश <netinet/in.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <time.h>
#समावेश <unistd.h>
#समावेश <limits.h>

#समावेश "sshlogin.h"
#समावेश "ssherr.h"
#समावेश "loginrec.h"
#समावेश "log.h"
#समावेश "sshbuf.h"
#समावेश "misc.h"
#समावेश "servconf.h"

बाह्य काष्ठा sshbuf *loginmsg;
बाह्य ServerOptions options;

/*
 * Returns the time when the user last logged in.  Returns 0 if the
 * information is not available.  This must be called before record_login.
 * The host the user logged in from will be returned in buf.
 */
समय_प्रकार
get_last_login_time(uid_t uid, स्थिर अक्षर *logname,
    अक्षर *buf, माप_प्रकार bufsize)
{
	काष्ठा logininfo li;

	login_get_lastlog(&li, uid);
	strlcpy(buf, li.hostname, bufsize);
	वापस (समय_प्रकार)li.tv_sec;
}

/*
 * Generate and store last login message.  This must be done before
 * login_login() is called and lastlog is updated.
 */
अटल व्योम
store_lastlog_message(स्थिर अक्षर *user, uid_t uid)
{
#अगर_अघोषित NO_SSH_LASTLOG
# ifndef CUSTOM_SYS_AUTH_GET_LASTLOGIN_संदेश
	अक्षर hostname[HOST_NAME_MAX+1] = "";
	समय_प्रकार last_login_time;
# endif
	अक्षर *time_string;
	पूर्णांक r;

	अगर (!options.print_lastlog)
		वापस;

# ifdef CUSTOM_SYS_AUTH_GET_LASTLOGIN_संदेश
	time_string = sys_auth_get_lastlogin_संदेश(user, uid);
	अगर (time_string != शून्य) {
		अगर ((r = sshbuf_put(loginmsg,
		    time_string, म_माप(time_string))) != 0)
			fatal_fr(r, "buffer error");
		मुक्त(time_string);
	}
# अन्यथा
	last_login_time = get_last_login_time(uid, user, hostname,
	    माप(hostname));

	अगर (last_login_time != 0) {
		time_string = स_समय(&last_login_time);
		time_string[म_खोज(time_string, "\n")] = '\0';
		अगर (म_भेद(hostname, "") == 0)
			r = sshbuf_putf(loginmsg, "Last login: %s\r\n",
			    time_string);
		अन्यथा
			r = sshbuf_putf(loginmsg, "Last login: %s from %s\r\n",
			    time_string, hostname);
		अगर (r != 0)
			fatal_fr(r, "sshbuf_putf");
	}
# endif /* CUSTOM_SYS_AUTH_GET_LASTLOGIN_MSG */
#पूर्ण_अगर /* NO_SSH_LASTLOG */
}

/*
 * Records that the user has logged in.  I wish these parts of operating
 * systems were more standardized.
 */
व्योम
record_login(pid_t pid, स्थिर अक्षर *tty, स्थिर अक्षर *user, uid_t uid,
    स्थिर अक्षर *host, काष्ठा sockaddr *addr, socklen_t addrlen)
{
	काष्ठा logininfo *li;

	/* save previous login details before writing new */
	store_lastlog_message(user, uid);

	li = login_alloc_entry(pid, user, host, tty);
	login_set_addr(li, addr, addrlen);
	login_login(li);
	login_free_entry(li);
}

#अगर_घोषित LOGIN_NEEDS_UTMPX
व्योम
record_utmp_only(pid_t pid, स्थिर अक्षर *ttyname, स्थिर अक्षर *user,
		 स्थिर अक्षर *host, काष्ठा sockaddr *addr, socklen_t addrlen)
{
	काष्ठा logininfo *li;

	li = login_alloc_entry(pid, user, host, ttyname);
	login_set_addr(li, addr, addrlen);
	login_utmp_only(li);
	login_free_entry(li);
}
#पूर्ण_अगर

/* Records that the user has logged out. */
व्योम
record_logout(pid_t pid, स्थिर अक्षर *tty, स्थिर अक्षर *user)
{
	काष्ठा logininfo *li;

	li = login_alloc_entry(pid, user, शून्य, tty);
	login_logout(li);
	login_free_entry(li);
}
