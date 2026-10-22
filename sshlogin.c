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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>

#அந்தர்பாவ <netinet/in.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>

#அந்தர்பாவ "sshlogin.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "loginrec.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"

வெளி கட்டமைப்பு sshbuf *loginmsg;
வெளி ServerOptions options;

/*
 * Returns the time when the user last logged in.  Returns 0 if the
 * information is not available.  This must be called before record_login.
 * The host the user logged in from will be returned in buf.
 */
time_t
get_last_login_time(uid_t uid, மாறிலி எழுத்து *logname,
    எழுத்து *buf, size_t bufsize)
{
	கட்டமைப்பு logininfo li;

	login_get_lastlog(&li, uid);
	strlcpy(buf, li.hostname, bufsize);
	திரும்பு (time_t)li.tv_sec;
}

/*
 * Generate and store last login message.  This must be done before
 * login_login() is called and lastlog is updated.
 */
நிலையான வெறுமை
store_lastlog_message(மாறிலி எழுத்து *user, uid_t uid)
{
#ifndef NO_SSH_LASTLOG
# ifndef CUSTOM_SYS_AUTH_GET_LASTLOGIN_செய்தி
	எழுத்து hostname[HOST_NAME_MAX+1] = "";
	time_t last_login_time;
# endif
	எழுத்து *time_string;
	முழு r;

	எனில் (!options.print_lastlog)
		திரும்பு;

# ifdef CUSTOM_SYS_AUTH_GET_LASTLOGIN_செய்தி
	time_string = sys_auth_get_lastlogin_செய்தி(user, uid);
	எனில் (time_string != வெற்று) {
		எனில் ((r = sshbuf_put(loginmsg,
		    time_string, strlen(time_string))) != 0)
			fatal_fr(r, "buffer error");
		விடுவி(time_string);
	}
# இல்லையெனில்
	last_login_time = get_last_login_time(uid, user, hostname,
	    அளவு(hostname));

	எனில் (last_login_time != 0) {
		time_string = ctime(&last_login_time);
		time_string[strcspn(time_string, "\n")] = '\0';
		எனில் (strcmp(hostname, "") == 0)
			r = sshbuf_putf(loginmsg, "Last login: %s\r\n",
			    time_string);
		இல்லையெனில்
			r = sshbuf_putf(loginmsg, "Last login: %s from %s\r\n",
			    time_string, hostname);
		எனில் (r != 0)
			fatal_fr(r, "sshbuf_putf");
	}
# endif /* CUSTOM_SYS_AUTH_GET_LASTLOGIN_MSG */
#endif /* NO_SSH_LASTLOG */
}

/*
 * Records that the user has logged in.  I wish these parts of operating
 * systems were more standardized.
 */
வெறுமை
record_login(pid_t pid, மாறிலி எழுத்து *tty, மாறிலி எழுத்து *user, uid_t uid,
    மாறிலி எழுத்து *host, கட்டமைப்பு sockaddr *addr, socklen_t addrlen)
{
	கட்டமைப்பு logininfo *li;

	/* save previous login details before writing new */
	store_lastlog_message(user, uid);

	li = login_alloc_entry(pid, user, host, tty);
	login_set_addr(li, addr, addrlen);
	login_login(li);
	login_free_entry(li);
}

#ifdef LOGIN_NEEDS_UTMPX
வெறுமை
record_utmp_only(pid_t pid, மாறிலி எழுத்து *ttyname, மாறிலி எழுத்து *user,
		 மாறிலி எழுத்து *host, கட்டமைப்பு sockaddr *addr, socklen_t addrlen)
{
	கட்டமைப்பு logininfo *li;

	li = login_alloc_entry(pid, user, host, ttyname);
	login_set_addr(li, addr, addrlen);
	login_utmp_only(li);
	login_free_entry(li);
}
#endif

/* Records that the user has logged out. */
வெறுமை
record_logout(pid_t pid, மாறிலி எழுத்து *tty, மாறிலி எழுத்து *user)
{
	கட்டமைப்பு logininfo *li;

	li = login_alloc_entry(pid, user, வெற்று, tty);
	login_logout(li);
	login_free_entry(li);
}
