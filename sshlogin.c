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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "sshlogin.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "loginrec.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"

ਬਾਹਰੀ ਬਣਤਰ sshbuf *loginmsg;
ਬਾਹਰੀ ServerOptions options;

/*
 * Returns the time when the user last logged in.  Returns 0 if the
 * information is not available.  This must be called before record_login.
 * The host the user logged in from will be returned in buf.
 */
time_t
get_ਆਖਰੀ_login_ਸਮਾਂ(uid_t uid, ਅਚਲ ਅੱਖਰ *logname,
    ਅੱਖਰ *buf, ਮਾਪ_t bufsize)
{
	ਬਣਤਰ logininfo li;

	login_get_lastlog(&li, uid);
	strlcpy(buf, li.hostname, bufsize);
	ਵਾਪਸ (time_t)li.tv_sec;
}

/*
 * Generate and store last login message.  This must be done before
 * login_login() is called and lastlog is updated.
 */
ਸਥਿਰ ਖਾਲੀ
store_lastlog_ਸੁਨੇਹਾ(ਅਚਲ ਅੱਖਰ *user, uid_t uid)
{
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ NO_SSH_LASTLOG
# ifndef CUSTOM_SYS_AUTH_GET_LASTLOGIN_ਸੁਨੇਹਾ
	ਅੱਖਰ hostname[HOST_NAME_MAX+1] = "";
	time_t ਆਖਰੀ_login_ਸਮਾਂ;
# endif
	ਅੱਖਰ *ਸਮਾਂ_string;
	ਪੂਰਨ r;

	ਜੇ (!options.print_lastlog)
		ਵਾਪਸ;

# ifdef CUSTOM_SYS_AUTH_GET_LASTLOGIN_ਸੁਨੇਹਾ
	ਸਮਾਂ_string = sys_auth_get_lastlogin_ਸੁਨੇਹਾ(user, uid);
	ਜੇ (ਸਮਾਂ_string != ਨਿਰਾ) {
		ਜੇ ((r = sshbuf_put(loginmsg,
		    ਸਮਾਂ_string, ਲੜੀ_ਲੰਬਾਈ(ਸਮਾਂ_string))) != 0)
			fatal_fr(r, "buffer error");
		ਮੁਕਤ(ਸਮਾਂ_string);
	}
# ਨਹੀਂਤਾਂ
	ਆਖਰੀ_login_ਸਮਾਂ = get_ਆਖਰੀ_login_ਸਮਾਂ(uid, user, hostname,
	    ਆਕਾਰ(hostname));

	ਜੇ (ਆਖਰੀ_login_ਸਮਾਂ != 0) {
		ਸਮਾਂ_string = ctime(&ਆਖਰੀ_login_ਸਮਾਂ);
		ਸਮਾਂ_string[strcspn(ਸਮਾਂ_string, "\n")] = '\0';
		ਜੇ (strcmp(hostname, "") == 0)
			r = sshbuf_putf(loginmsg, "Last login: %s\r\n",
			    ਸਮਾਂ_string);
		ਨਹੀਂਤਾਂ
			r = sshbuf_putf(loginmsg, "Last login: %s from %s\r\n",
			    ਸਮਾਂ_string, hostname);
		ਜੇ (r != 0)
			fatal_fr(r, "sshbuf_putf");
	}
# endif /* CUSTOM_SYS_AUTH_GET_LASTLOGIN_MSG */
#ਜੇ_ਅੰਤ /* NO_SSH_LASTLOG */
}

/*
 * Records that the user has logged in.  I wish these parts of operating
 * systems were more standardized.
 */
ਖਾਲੀ
ਰਿਕਾਰਡ_login(pid_t pid, ਅਚਲ ਅੱਖਰ *tty, ਅਚਲ ਅੱਖਰ *user, uid_t uid,
    ਅਚਲ ਅੱਖਰ *host, ਬਣਤਰ sockaddr *addr, socklen_t addrlen)
{
	ਬਣਤਰ logininfo *li;

	/* save previous login details before writing new */
	store_lastlog_ਸੁਨੇਹਾ(user, uid);

	li = login_alloc_ਇੰਦਰਾਜ(pid, user, host, tty);
	login_ਸੈੱਟ_addr(li, addr, addrlen);
	login_login(li);
	login_free_ਇੰਦਰਾਜ(li);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LOGIN_NEEDS_UTMPX
ਖਾਲੀ
ਰਿਕਾਰਡ_utmp_only(pid_t pid, ਅਚਲ ਅੱਖਰ *ttyname, ਅਚਲ ਅੱਖਰ *user,
		 ਅਚਲ ਅੱਖਰ *host, ਬਣਤਰ sockaddr *addr, socklen_t addrlen)
{
	ਬਣਤਰ logininfo *li;

	li = login_alloc_ਇੰਦਰਾਜ(pid, user, host, ttyname);
	login_ਸੈੱਟ_addr(li, addr, addrlen);
	login_utmp_only(li);
	login_free_ਇੰਦਰਾਜ(li);
}
#ਜੇ_ਅੰਤ

/* Records that the user has logged out. */
ਖਾਲੀ
ਰਿਕਾਰਡ_logout(pid_t pid, ਅਚਲ ਅੱਖਰ *tty, ਅਚਲ ਅੱਖਰ *user)
{
	ਬਣਤਰ logininfo *li;

	li = login_alloc_ਇੰਦਰਾਜ(pid, user, ਨਿਰਾ, tty);
	login_logout(li);
	login_free_ਇੰਦਰਾਜ(li);
}
