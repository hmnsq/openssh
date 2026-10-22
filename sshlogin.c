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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>

#అన్తర్భావ <netinet/in.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>

#అన్తర్భావ "sshlogin.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "loginrec.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"

బాహ్య నిర్మాణం sshbuf *loginmsg;
బాహ్య ServerOptions options;

/*
 * Returns the time when the user last logged in.  Returns 0 if the
 * information is not available.  This must be called before record_login.
 * The host the user logged in from will be returned in buf.
 */
time_t
get_చివరి_login_సమయం(uid_t uid, స్థిరరాశి అక్షరం *logname,
    అక్షరం *buf, కొలత_t bufsize)
{
	నిర్మాణం logininfo li;

	login_get_lastlog(&li, uid);
	strlcpy(buf, li.hostname, bufsize);
	తిరిగి (time_t)li.tv_sec;
}

/*
 * Generate and store last login message.  This must be done before
 * login_login() is called and lastlog is updated.
 */
స్థిర శూన్య
store_lastlog_సందేశం(స్థిరరాశి అక్షరం *user, uid_t uid)
{
#నిర్వచితం_కాకపోతే NO_SSH_LASTLOG
# ifndef CUSTOM_SYS_AUTH_GET_LASTLOGIN_సందేశం
	అక్షరం hostname[HOST_NAME_MAX+1] = "";
	time_t చివరి_login_సమయం;
# endif
	అక్షరం *సమయం_string;
	పూర్ణాంకం r;

	ఒకవేళ (!options.print_lastlog)
		తిరిగి;

# ifdef CUSTOM_SYS_AUTH_GET_LASTLOGIN_సందేశం
	సమయం_string = sys_auth_get_lastlogin_సందేశం(user, uid);
	ఒకవేళ (సమయం_string != ఖాళీ) {
		ఒకవేళ ((r = sshbuf_put(loginmsg,
		    సమయం_string, అక్షరశ్రేణి_పొడవు(సమయం_string))) != 0)
			fatal_fr(r, "buffer error");
		విడుదల(సమయం_string);
	}
# లేకపోతే
	చివరి_login_సమయం = get_చివరి_login_సమయం(uid, user, hostname,
	    పరిమాణం(hostname));

	ఒకవేళ (చివరి_login_సమయం != 0) {
		సమయం_string = ctime(&చివరి_login_సమయం);
		సమయం_string[strcspn(సమయం_string, "\n")] = '\0';
		ఒకవేళ (strcmp(hostname, "") == 0)
			r = sshbuf_putf(loginmsg, "Last login: %s\r\n",
			    సమయం_string);
		లేకపోతే
			r = sshbuf_putf(loginmsg, "Last login: %s from %s\r\n",
			    సమయం_string, hostname);
		ఒకవేళ (r != 0)
			fatal_fr(r, "sshbuf_putf");
	}
# endif /* CUSTOM_SYS_AUTH_GET_LASTLOGIN_MSG */
#అయితే_ముగింపు /* NO_SSH_LASTLOG */
}

/*
 * Records that the user has logged in.  I wish these parts of operating
 * systems were more standardized.
 */
శూన్య
రికార్డు_login(pid_t pid, స్థిరరాశి అక్షరం *tty, స్థిరరాశి అక్షరం *user, uid_t uid,
    స్థిరరాశి అక్షరం *host, నిర్మాణం sockaddr *addr, socklen_t addrlen)
{
	నిర్మాణం logininfo *li;

	/* save previous login details before writing new */
	store_lastlog_సందేశం(user, uid);

	li = login_alloc_నమోదు(pid, user, host, tty);
	login_సమితి_addr(li, addr, addrlen);
	login_login(li);
	login_free_నమోదు(li);
}

#నిర్వచితమైతే LOGIN_NEEDS_UTMPX
శూన్య
రికార్డు_utmp_only(pid_t pid, స్థిరరాశి అక్షరం *ttyname, స్థిరరాశి అక్షరం *user,
		 స్థిరరాశి అక్షరం *host, నిర్మాణం sockaddr *addr, socklen_t addrlen)
{
	నిర్మాణం logininfo *li;

	li = login_alloc_నమోదు(pid, user, host, ttyname);
	login_సమితి_addr(li, addr, addrlen);
	login_utmp_only(li);
	login_free_నమోదు(li);
}
#అయితే_ముగింపు

/* Records that the user has logged out. */
శూన్య
రికార్డు_logout(pid_t pid, స్థిరరాశి అక్షరం *tty, స్థిరరాశి అక్షరం *user)
{
	నిర్మాణం logininfo *li;

	li = login_alloc_నమోదు(pid, user, ఖాళీ, tty);
	login_logout(li);
	login_free_నమోదు(li);
}
