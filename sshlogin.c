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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>

#അന്തര്ഭാവ <netinet/in.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>

#അന്തര്ഭാവ "sshlogin.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "loginrec.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"

ബാഹ്യ ഘടന sshbuf *loginmsg;
ബാഹ്യ ServerOptions options;

/*
 * Returns the time when the user last logged in.  Returns 0 if the
 * information is not available.  This must be called before record_login.
 * The host the user logged in from will be returned in buf.
 */
time_t
get_last_login_time(uid_t uid, സ്ഥിരം അക്ഷരം *logname,
    അക്ഷരം *buf, size_t bufsize)
{
	ഘടന logininfo li;

	login_get_lastlog(&li, uid);
	strlcpy(buf, li.hostname, bufsize);
	തിരികെ (time_t)li.tv_sec;
}

/*
 * Generate and store last login message.  This must be done before
 * login_login() is called and lastlog is updated.
 */
സ്ഥിതം ശൂന്യം
store_lastlog_message(സ്ഥിരം അക്ഷരം *user, uid_t uid)
{
#ifndef NO_SSH_LASTLOG
# ifndef CUSTOM_SYS_AUTH_GET_LASTLOGIN_സന്ദേശം
	അക്ഷരം hostname[HOST_NAME_MAX+1] = "";
	time_t last_login_time;
# endif
	അക്ഷരം *time_string;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (!options.print_lastlog)
		തിരികെ;

# ifdef CUSTOM_SYS_AUTH_GET_LASTLOGIN_സന്ദേശം
	time_string = sys_auth_get_lastlogin_സന്ദേശം(user, uid);
	എങ്കിൽ (time_string != ശൂന്യ) {
		എങ്കിൽ ((r = sshbuf_put(loginmsg,
		    time_string, strlen(time_string))) != 0)
			fatal_fr(r, "buffer error");
		സ്വതന്ത്രം(time_string);
	}
# അല്ലെങ്കിൽ
	last_login_time = get_last_login_time(uid, user, hostname,
	    വലുപ്പം(hostname));

	എങ്കിൽ (last_login_time != 0) {
		time_string = ctime(&last_login_time);
		time_string[strcspn(time_string, "\n")] = '\0';
		എങ്കിൽ (strcmp(hostname, "") == 0)
			r = sshbuf_putf(loginmsg, "Last login: %s\r\n",
			    time_string);
		അല്ലെങ്കിൽ
			r = sshbuf_putf(loginmsg, "Last login: %s from %s\r\n",
			    time_string, hostname);
		എങ്കിൽ (r != 0)
			fatal_fr(r, "sshbuf_putf");
	}
# endif /* CUSTOM_SYS_AUTH_GET_LASTLOGIN_MSG */
#endif /* NO_SSH_LASTLOG */
}

/*
 * Records that the user has logged in.  I wish these parts of operating
 * systems were more standardized.
 */
ശൂന്യം
record_login(pid_t pid, സ്ഥിരം അക്ഷരം *tty, സ്ഥിരം അക്ഷരം *user, uid_t uid,
    സ്ഥിരം അക്ഷരം *host, ഘടന sockaddr *addr, socklen_t addrlen)
{
	ഘടന logininfo *li;

	/* save previous login details before writing new */
	store_lastlog_message(user, uid);

	li = login_alloc_entry(pid, user, host, tty);
	login_set_addr(li, addr, addrlen);
	login_login(li);
	login_free_entry(li);
}

#ifdef LOGIN_NEEDS_UTMPX
ശൂന്യം
record_utmp_only(pid_t pid, സ്ഥിരം അക്ഷരം *ttyname, സ്ഥിരം അക്ഷരം *user,
		 സ്ഥിരം അക്ഷരം *host, ഘടന sockaddr *addr, socklen_t addrlen)
{
	ഘടന logininfo *li;

	li = login_alloc_entry(pid, user, host, ttyname);
	login_set_addr(li, addr, addrlen);
	login_utmp_only(li);
	login_free_entry(li);
}
#endif

/* Records that the user has logged out. */
ശൂന്യം
record_logout(pid_t pid, സ്ഥിരം അക്ഷരം *tty, സ്ഥിരം അക്ഷരം *user)
{
	ഘടന logininfo *li;

	li = login_alloc_entry(pid, user, ശൂന്യ, tty);
	login_logout(li);
	login_free_entry(li);
}
