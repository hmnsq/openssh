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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

#ଅନ୍ତର୍ଭାଵ "sshlogin.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "loginrec.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"

ବାହ୍ୟ ସଂରଚନା sshbuf *loginmsg;
ବାହ୍ୟ ServerOptions options;

/*
 * Returns the time when the user last logged in.  Returns 0 if the
 * information is not available.  This must be called before record_login.
 * The host the user logged in from will be returned in buf.
 */
time_t
get_last_login_time(uid_t uid, ଅଚଳ ଅକ୍ଷର *logname,
    ଅକ୍ଷର *buf, size_t bufsize)
{
	ସଂରଚନା logininfo li;

	login_get_lastlog(&li, uid);
	strlcpy(buf, li.hostname, bufsize);
	ଫେରନ୍ତୁ (time_t)li.tv_sec;
}

/*
 * Generate and store last login message.  This must be done before
 * login_login() is called and lastlog is updated.
 */
ସ୍ଥିର ଶୂନ୍ୟ
store_lastlog_message(ଅଚଳ ଅକ୍ଷର *user, uid_t uid)
{
#ifndef NO_SSH_LASTLOG
# ifndef CUSTOM_SYS_AUTH_GET_LASTLOGIN_ସନ୍ଦେଶ
	ଅକ୍ଷର hostname[HOST_NAME_MAX+1] = "";
	time_t last_login_time;
# endif
	ଅକ୍ଷର *time_string;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (!options.print_lastlog)
		ଫେରନ୍ତୁ;

# ifdef CUSTOM_SYS_AUTH_GET_LASTLOGIN_ସନ୍ଦେଶ
	time_string = sys_auth_get_lastlogin_ସନ୍ଦେଶ(user, uid);
	ଯଦି (time_string != ଖାଲି) {
		ଯଦି ((r = sshbuf_put(loginmsg,
		    time_string, strlen(time_string))) != 0)
			fatal_fr(r, "buffer error");
		ମୁକ୍ତ(time_string);
	}
# ଅନ୍ୟଥା
	last_login_time = get_last_login_time(uid, user, hostname,
	    ଆକାର(hostname));

	ଯଦି (last_login_time != 0) {
		time_string = ctime(&last_login_time);
		time_string[strcspn(time_string, "\n")] = '\0';
		ଯଦି (strcmp(hostname, "") == 0)
			r = sshbuf_putf(loginmsg, "Last login: %s\r\n",
			    time_string);
		ଅନ୍ୟଥା
			r = sshbuf_putf(loginmsg, "Last login: %s from %s\r\n",
			    time_string, hostname);
		ଯଦି (r != 0)
			fatal_fr(r, "sshbuf_putf");
	}
# endif /* CUSTOM_SYS_AUTH_GET_LASTLOGIN_MSG */
#endif /* NO_SSH_LASTLOG */
}

/*
 * Records that the user has logged in.  I wish these parts of operating
 * systems were more standardized.
 */
ଶୂନ୍ୟ
record_login(pid_t pid, ଅଚଳ ଅକ୍ଷର *tty, ଅଚଳ ଅକ୍ଷର *user, uid_t uid,
    ଅଚଳ ଅକ୍ଷର *host, ସଂରଚନା sockaddr *addr, socklen_t addrlen)
{
	ସଂରଚନା logininfo *li;

	/* save previous login details before writing new */
	store_lastlog_message(user, uid);

	li = login_alloc_entry(pid, user, host, tty);
	login_set_addr(li, addr, addrlen);
	login_login(li);
	login_free_entry(li);
}

#ifdef LOGIN_NEEDS_UTMPX
ଶୂନ୍ୟ
record_utmp_only(pid_t pid, ଅଚଳ ଅକ୍ଷର *ttyname, ଅଚଳ ଅକ୍ଷର *user,
		 ଅଚଳ ଅକ୍ଷର *host, ସଂରଚନା sockaddr *addr, socklen_t addrlen)
{
	ସଂରଚନା logininfo *li;

	li = login_alloc_entry(pid, user, host, ttyname);
	login_set_addr(li, addr, addrlen);
	login_utmp_only(li);
	login_free_entry(li);
}
#endif

/* Records that the user has logged out. */
ଶୂନ୍ୟ
record_logout(pid_t pid, ଅଚଳ ଅକ୍ଷର *tty, ଅଚଳ ଅକ୍ଷର *user)
{
	ସଂରଚନା logininfo *li;

	li = login_alloc_entry(pid, user, ଖାଲି, tty);
	login_logout(li);
	login_free_entry(li);
}
