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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>

#شامل <netinet/in.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <time.h>
#شامل <unistd.h>
#شامل <limits.h>

#شامل "sshlogin.h"
#شامل "ssherr.h"
#شامل "loginrec.h"
#شامل "log.h"
#شامل "sshbuf.h"
#شامل "misc.h"
#شامل "servconf.h"

خارجی ساخت sshbuf *loginmsg;
خارجی ServerOptions options;

/*
 * Returns the time when the user last logged in.  Returns 0 if the
 * information is not available.  This must be called before record_login.
 * The host the user logged in from will be returned in buf.
 */
time_t
get_آخری_login_وقت(uid_t uid, ثابت حرف *logname,
    حرف *buf, سائز_t bufsize)
{
	ساخت logininfo li;

	login_get_lastlog(&li, uid);
	strlcpy(buf, li.hostname, bufsize);
	واپس (time_t)li.tv_sec;
}

/*
 * Generate and store last login message.  This must be done before
 * login_login() is called and lastlog is updated.
 */
ساکن خالی
store_lastlog_پیغام(ثابت حرف *user, uid_t uid)
{
#اگر_غیر_تعریف_شدہ NO_SSH_LASTLOG
# ifndef CUSTOM_SYS_AUTH_GET_LASTLOGIN_پیغام
	حرف hostname[HOST_NAME_MAX+1] = "";
	time_t آخری_login_وقت;
# endif
	حرف *وقت_string;
	صحیح r;

	اگر (!options.print_lastlog)
		واپس;

# ifdef CUSTOM_SYS_AUTH_GET_LASTLOGIN_پیغام
	وقت_string = sys_auth_get_lastlogin_پیغام(user, uid);
	اگر (وقت_string != تہی) {
		اگر ((r = sshbuf_put(loginmsg,
		    وقت_string, لڑی_لمبائی(وقت_string))) != 0)
			fatal_fr(r, "buffer error");
		آزاد(وقت_string);
	}
# ورنہ
	آخری_login_وقت = get_آخری_login_وقت(uid, user, hostname,
	    حجم(hostname));

	اگر (آخری_login_وقت != 0) {
		وقت_string = ctime(&آخری_login_وقت);
		وقت_string[strcspn(وقت_string, "\n")] = '\0';
		اگر (strcmp(hostname, "") == 0)
			r = sshbuf_putf(loginmsg, "Last login: %s\r\n",
			    وقت_string);
		ورنہ
			r = sshbuf_putf(loginmsg, "Last login: %s from %s\r\n",
			    وقت_string, hostname);
		اگر (r != 0)
			fatal_fr(r, "sshbuf_putf");
	}
# endif /* CUSTOM_SYS_AUTH_GET_LASTLOGIN_MSG */
#اگر_ختم /* NO_SSH_LASTLOG */
}

/*
 * Records that the user has logged in.  I wish these parts of operating
 * systems were more standardized.
 */
خالی
ریکارڈ_login(pid_t pid, ثابت حرف *tty, ثابت حرف *user, uid_t uid,
    ثابت حرف *host, ساخت sockaddr *addr, socklen_t addrlen)
{
	ساخت logininfo *li;

	/* save previous login details before writing new */
	store_lastlog_پیغام(user, uid);

	li = login_alloc_اندراج(pid, user, host, tty);
	login_سیٹ_addr(li, addr, addrlen);
	login_login(li);
	login_free_اندراج(li);
}

#اگر_تعریف_شدہ LOGIN_NEEDS_UTMPX
خالی
ریکارڈ_utmp_only(pid_t pid, ثابت حرف *ttyname, ثابت حرف *user,
		 ثابت حرف *host, ساخت sockaddr *addr, socklen_t addrlen)
{
	ساخت logininfo *li;

	li = login_alloc_اندراج(pid, user, host, ttyname);
	login_سیٹ_addr(li, addr, addrlen);
	login_utmp_only(li);
	login_free_اندراج(li);
}
#اگر_ختم

/* Records that the user has logged out. */
خالی
ریکارڈ_logout(pid_t pid, ثابت حرف *tty, ثابت حرف *user)
{
	ساخت logininfo *li;

	li = login_alloc_اندراج(pid, user, تہی, tty);
	login_logout(li);
	login_free_اندراج(li);
}
