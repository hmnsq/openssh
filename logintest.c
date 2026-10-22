/*
 * Copyright (c) 2000 Andre Lucas.  All rights reserved.
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

/**
 ** logintest.c:  simple test driver for platform-independent login recording
 **               and lastlog retrieval
 **/

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/wait.h>
#شامل <sys/socket.h>

#شامل <netinet/in.h>

#شامل <unistd.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <pwd.h>
#شامل <netdb.h>
#شامل <time.h>

#شامل "loginrec.h"

خارجی حرف *__progname;

#تعریف_کرو PAUSE_BEFORE_LOGOUT 3

صحیح nologtest = 0;
صحیح compile_opts_only = 0;
صحیح be_verbose = 0;


/* Dump a logininfo to stdout. Assumes a tab size of 8 chars. */
خالی
dump_logininfo(ساخت logininfo *li, حرف *descname)
{
	/* yes I know how nasty this is */
	لکھو("struct logininfo %s = {\n\t"
	    "progname\t'%s'\n\ttype\t\t%d\n\t"
	    "pid\t\t%d\n\tuid\t\t%d\n\t"
	    "line\t\t'%s'\n\tusername\t'%s'\n\t"
	    "hostname\t'%s'\n\texit\t\t%d\n\ttermination\t%d\n\t"
	    "tv_sec\t%d\n\ttv_usec\t%d\n\t"
	    "struct login_netinfo hostaddr {\n\t\t"
	    "struct sockaddr sa {\n"
	    "\t\t\tfamily\t%d\n\t\t}\n"
	    "\t}\n"
	    "}\n",
	    descname, li->progname, li->type,
	    li->pid, li->uid, li->سطر,
	    li->username, li->hostname, li->باہر_نکلو,
	    li->termination, li->tv_sec, li->tv_usec,
	    li->hostaddr.sa.sa_family);
}


صحیح
testAPI()
{
	ساخت logininfo *li1;
	ساخت passwd *pw;
	ساخت hostent *he;
	ساخت sockaddr_in sa_in4;
	حرف cmdstring[256], stripline[8];
	حرف username[32];
#اگر_تعریف_شدہ HAVE_وقت_H
	time_t t0, t1, t2, logintime, logouttime;
	حرف s_t0[64],s_t1[64],s_t2[64];
	حرف s_logintime[64], s_logouttime[64]; /* ctime() strings */
#اگر_ختم

	لکھو("**\n** Testing the API...\n**\n");

	pw = getpwuid(getuid());
	strlcpy(username, pw->pw_name, حجم(username));

	/* gethostname(hostname, sizeof(hostname)); */

	لکھو("login_alloc_entry test (no host info):\n");

	/* FIXME fake tty more effectively - this could upset some platforms */
	li1 = login_alloc_اندراج((صحیح)getpid(), username, تہی, ttyname(0));
	strlcpy(li1->progname, "OpenSSH-logintest", حجم(li1->progname));

	اگر (be_verbose)
		dump_logininfo(li1, "li1");

	لکھو("Setting host address info for 'localhost' (may call out):\n");
	اگر (! (he = gethostbyname("localhost"))) {
		لکھو("Couldn't set hostname(lookup failed)\n");
	} ورنہ {
		/* NOTE: this is messy, but typically a program wouldn't have to set
		 *  any of this, a sockaddr_in* would be already prepared */
		حافظہ_نقل((خالی *)&(sa_in4.sin_addr), (خالی *)&(he->h_addr_list[0][0]),
		    حجم(ساخت in_addr));
		login_سیٹ_addr(li1, (ساخت sockaddr *) &sa_in4, حجم(sa_in4));
		strlcpy(li1->hostname, "localhost", حجم(li1->hostname));
	}
	اگر (be_verbose)
		dump_logininfo(li1, "li1");

	اگر ((صحیح)geteuid() != 0) {
		لکھو("NOT RUNNING LOGIN TESTS - you are not root!\n");
		واپس 1;
	}

	اگر (nologtest)
		واپس 1;

	سطر_stripname(stripline, li1->سطر, حجم(stripline));

	لکھو("Performing an invalid login attempt (no type field)\n--\n");
	login_write(li1);
	لکھو("--\n(Should have written errors to stderr)\n");

#اگر_تعریف_شدہ HAVE_وقت_H
	(خالی)time(&t0);
	strlcpy(s_t0, ctime(&t0), حجم(s_t0));
	t1 = login_get_lastlog_وقت(getuid());
	strlcpy(s_t1, ctime(&t1), حجم(s_t1));
	لکھو("Before logging in:\n\tcurrent time is %d - %s\t"
	    "lastlog time is %d - %s\n",
	    (صحیح)t0, s_t0, (صحیح)t1, s_t1);
#اگر_ختم

	لکھو("Performing a login on line %s ", stripline);
#اگر_تعریف_شدہ HAVE_وقت_H
	(خالی)time(&logintime);
	strlcpy(s_logintime, ctime(&logintime), حجم(s_logintime));
	لکھو("at %d - %s", (صحیح)logintime, s_logintime);
#اگر_ختم
	لکھو("--\n");
	login_login(li1);

	snprintf(cmdstring, حجم(cmdstring), "who | grep '%s '",
		 stripline);
	system(cmdstring);

	لکھو("--\nPausing for %d second(s)...\n", PAUSE_BEFORE_LOGOUT);
	sleep(PAUSE_BEFORE_LOGOUT);

	لکھو("Performing a logout ");
#اگر_تعریف_شدہ HAVE_وقت_H
	(خالی)time(&logouttime);
	strlcpy(s_logouttime, ctime(&logouttime), حجم(s_logouttime));
	لکھو("at %d - %s", (صحیح)logouttime, s_logouttime);
#اگر_ختم
	لکھو("\nThe root login shown above should be gone.\n"
	    "If the root login hasn't gone, but another user on the same\n"
	    "pty has, this is OK - we're hacking it here, and there\n"
	    "shouldn't be two users on one pty in reality...\n"
	    "-- ('who' output follows)\n");
	login_logout(li1);

	system(cmdstring);
	لکھو("-- ('who' output ends)\n");

#اگر_تعریف_شدہ HAVE_وقت_H
	t2 = login_get_lastlog_وقت(getuid());
	strlcpy(s_t2, ctime(&t2), حجم(s_t2));
	لکھو("After logging in, lastlog time is %d - %s\n", (صحیح)t2, s_t2);
	اگر (t1 == t2)
		لکھو("The lastlog times before and after logging in are the "
		    "same.\nThis indicates that lastlog is ** NOT WORKING "
		    "CORRECTLY **\n");
	ورنہ اگر (t0 != t2)
		/* We can be off by a second or so, even when recording works fine.
		 * I'm not 100% sure why, but it's true. */
		لکھو("** The login time and the lastlog time differ.\n"
		    "** This indicates that lastlog is either recording the "
		    "wrong time,\n** or retrieving the wrong entry.\n"
		    "If it's off by less than %d second(s) "
		    "run the test again.\n", PAUSE_BEFORE_LOGOUT);
	ورنہ
		لکھو("lastlog agrees with the login time. This is a good thing.\n");

#اگر_ختم

	لکھو("--\nThe output of 'last' shown next should have "
	    "an entry for root \n  on %s for the time shown above:\n--\n",
	    stripline);
	snprintf(cmdstring, حجم(cmdstring), "last | grep '%s ' | head -3",
		 stripline);
	system(cmdstring);

	لکھو("--\nEnd of login test.\n");

	login_free_اندراج(li1);

	واپس 1;
} /* testAPI() */


خالی
test_سطر_Name(حرف *سطر)
{
	/* have to null-terminate - these functions are designed for
	 * structures with fixed-length char arrays, and don't null-term.*/
	حرف بھرا[17], strip[9], abbrev[5];

	memset(بھرا, '\0', حجم(بھرا));
	memset(strip, '\0', حجم(strip));
	memset(abbrev, '\0', حجم(abbrev));

	سطر_fullname(بھرا, سطر, حجم(بھرا)-1);
	سطر_stripname(strip, بھرا, حجم(strip)-1);
	سطر_abbrevname(abbrev, بھرا, حجم(abbrev)-1);
	لکھو("%s: %s, %s, %s\n", سطر, بھرا, strip, abbrev);

} /* testLineName() */


صحیح
testOutput()
{
	لکھو("**\n** Testing linename functions\n**\n");
	test_سطر_Name("/dev/pts/1");
	test_سطر_Name("pts/1");
	test_سطر_Name("pts/999");
	test_سطر_Name("/dev/ttyp00");
	test_سطر_Name("ttyp00");

	واپس 1;
} /* testOutput() */


/* show which options got compiled in */
خالی
showOptions(خالی)
{
	لکھو("**\n** Compile-time options\n**\n");

	لکھو("login recording methods selected:\n");
#اگر_تعریف_شدہ USE_LOGIN
	لکھو("\tUSE_LOGIN\n");
#اگر_ختم
#اگر_تعریف_شدہ USE_UTMP
	لکھو("\tUSE_UTMP (UTMP_FILE=%s)\n", UTMP_FILE);
#اگر_ختم
#اگر_تعریف_شدہ USE_UTMPX
	لکھو("\tUSE_UTMPX\n");
#اگر_ختم
#اگر_تعریف_شدہ USE_WTMP
	لکھو("\tUSE_WTMP (WTMP_FILE=%s)\n", WTMP_FILE);
#اگر_ختم
#اگر_تعریف_شدہ USE_WTMPX
	لکھو("\tUSE_WTMPX (WTMPX_FILE=%s)\n", WTMPX_FILE);
#اگر_ختم
#اگر_تعریف_شدہ USE_LASTLOG
	لکھو("\tUSE_LASTLOG (LASTLOG_FILE=%s)\n", LASTLOG_FILE);
#اگر_ختم
	لکھو("\n");

} /* showOptions() */


صحیح
مین(صحیح argc, حرف *argv[])
{
	لکھو("Platform-independent login recording test driver\n");

	__progname = ssh_get_progname(argv[0]);
	اگر (argc == 2) {
		اگر (لڑی_موازنہ(argv[1], "-i", 3) == 0)
			compile_opts_only = 1;
		ورنہ اگر (لڑی_موازنہ(argv[1], "-v", 3) == 0)
			be_verbose=1;
	}

	اگر (!compile_opts_only) {
		اگر (be_verbose && !testOutput())
			واپس 1;

		اگر (!testAPI())
			واپس 1;
	}

	showOptions();

	واپس 0;
} /* main() */

