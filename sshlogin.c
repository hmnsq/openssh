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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/socket.h>

#অন্তর্ভাৱ <netinet/in.h>

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <time.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <limits.h>

#অন্তর্ভাৱ "sshlogin.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "loginrec.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "servconf.h"

বাহ্য সংরচনা sshbuf *loginmsg;
বাহ্য ServerOptions options;

/*
 * Returns the time when the user last logged in.  Returns 0 if the
 * information is not available.  This must be called before record_login.
 * The host the user logged in from will be returned in buf.
 */
time_t
get_last_login_time(uid_t uid, ধ্রুৱ ৱর্ণ *logname,
    ৱর্ণ *buf, size_t bufsize)
{
	সংরচনা logininfo li;

	login_get_lastlog(&li, uid);
	strlcpy(buf, li.hostname, bufsize);
	ঘূৰাই (time_t)li.tv_sec;
}

/*
 * Generate and store last login message.  This must be done before
 * login_login() is called and lastlog is updated.
 */
স্থির শূন্য
store_lastlog_message(ধ্রুৱ ৱর্ণ *user, uid_t uid)
{
#ifndef NO_SSH_LASTLOG
# ifndef CUSTOM_SYS_AUTH_GET_LASTLOGIN_বাৰ্তা
	ৱর্ণ hostname[HOST_NAME_MAX+1] = "";
	time_t last_login_time;
# endif
	ৱর্ণ *time_string;
	পূর্ণাঙ্ক r;

	যদি (!options.print_lastlog)
		ঘূৰাই;

# ifdef CUSTOM_SYS_AUTH_GET_LASTLOGIN_বাৰ্তা
	time_string = sys_auth_get_lastlogin_বাৰ্তা(user, uid);
	যদি (time_string != রিক্ত) {
		যদি ((r = sshbuf_put(loginmsg,
		    time_string, strlen(time_string))) != 0)
			fatal_fr(r, "buffer error");
		মুক্ত(time_string);
	}
# অন্যথা
	last_login_time = get_last_login_time(uid, user, hostname,
	    পরিমাণ(hostname));

	যদি (last_login_time != 0) {
		time_string = ctime(&last_login_time);
		time_string[strcspn(time_string, "\n")] = '\0';
		যদি (strcmp(hostname, "") == 0)
			r = sshbuf_putf(loginmsg, "Last login: %s\r\n",
			    time_string);
		অন্যথা
			r = sshbuf_putf(loginmsg, "Last login: %s from %s\r\n",
			    time_string, hostname);
		যদি (r != 0)
			fatal_fr(r, "sshbuf_putf");
	}
# endif /* CUSTOM_SYS_AUTH_GET_LASTLOGIN_MSG */
#endif /* NO_SSH_LASTLOG */
}

/*
 * Records that the user has logged in.  I wish these parts of operating
 * systems were more standardized.
 */
শূন্য
record_login(pid_t pid, ধ্রুৱ ৱর্ণ *tty, ধ্রুৱ ৱর্ণ *user, uid_t uid,
    ধ্রুৱ ৱর্ণ *host, সংরচনা sockaddr *addr, socklen_t addrlen)
{
	সংরচনা logininfo *li;

	/* save previous login details before writing new */
	store_lastlog_message(user, uid);

	li = login_alloc_entry(pid, user, host, tty);
	login_set_addr(li, addr, addrlen);
	login_login(li);
	login_free_entry(li);
}

#ifdef LOGIN_NEEDS_UTMPX
শূন্য
record_utmp_only(pid_t pid, ধ্রুৱ ৱর্ণ *ttyname, ধ্রুৱ ৱর্ণ *user,
		 ধ্রুৱ ৱর্ণ *host, সংরচনা sockaddr *addr, socklen_t addrlen)
{
	সংরচনা logininfo *li;

	li = login_alloc_entry(pid, user, host, ttyname);
	login_set_addr(li, addr, addrlen);
	login_utmp_only(li);
	login_free_entry(li);
}
#endif

/* Records that the user has logged out. */
শূন্য
record_logout(pid_t pid, ধ্রুৱ ৱর্ণ *tty, ধ্রুৱ ৱর্ণ *user)
{
	সংরচনা logininfo *li;

	li = login_alloc_entry(pid, user, রিক্ত, tty);
	login_logout(li);
	login_free_entry(li);
}
