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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/wait.h>
#ضمن <sys/socket.h>

#ضمن <netinet/in.h>

#ضمن <unistd.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <pwd.h>
#ضمن <netdb.h>
#ضمن <time.h>

#ضمن "loginrec.h"

خارجي حرف *__progname;

#وصف_ڪريو PAUSE_BEFORE_LOGOUT 3

صحيح nologtest = 0;
صحيح compile_opts_only = 0;
صحيح be_verbose = 0;


/* Dump a logininfo to stdout. Assumes a tab size of 8 chars. */
فراغ
dump_logininfo(بنية logininfo *li, حرف *descname)
{
	/* yes I know how nasty this is */
	لکو("struct logininfo %s = {\n\t"
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
	    li->pid, li->uid, li->سٽ,
	    li->username, li->hostname, li->ٻاهر_نڪرو,
	    li->termination, li->tv_sec, li->tv_usec,
	    li->hostaddr.sa.sa_family);
}


صحيح
testAPI()
{
	بنية logininfo *li1;
	بنية passwd *pw;
	بنية hostent *he;
	بنية sockaddr_in sa_in4;
	حرف cmdstring[256], stripline[8];
	حرف username[32];
#جيڪڏهن_وصف_ٿيل HAVE_وقت_H
	time_t t0, t1, t2, logintime, logouttime;
	حرف s_t0[64],s_t1[64],s_t2[64];
	حرف s_logintime[64], s_logouttime[64]; /* ctime() strings */
#جيڪڏهن_پورو

	لکو("**\n** Testing the API...\n**\n");

	pw = getpwuid(getuid());
	strlcpy(username, pw->pw_name, حجم(username));

	/* gethostname(hostname, sizeof(hostname)); */

	لکو("login_alloc_entry test (no host info):\n");

	/* FIXME fake tty more effectively - this could upset some platforms */
	li1 = login_alloc_داخلا((صحيح)getpid(), username, عدم, ttyname(0));
	strlcpy(li1->progname, "OpenSSH-logintest", حجم(li1->progname));

	إذا (be_verbose)
		dump_logininfo(li1, "li1");

	لکو("Setting host address info for 'localhost' (may call out):\n");
	إذا (! (he = gethostbyname("localhost"))) {
		لکو("Couldn't set hostname(lookup failed)\n");
	} وإلا {
		/* NOTE: this is messy, but typically a program wouldn't have to set
		 *  any of this, a sockaddr_in* would be already prepared */
		يادگيري_نقل((فراغ *)&(sa_in4.sin_addr), (فراغ *)&(he->h_addr_list[0][0]),
		    حجم(بنية in_addr));
		login_سيٽ_addr(li1, (بنية sockaddr *) &sa_in4, حجم(sa_in4));
		strlcpy(li1->hostname, "localhost", حجم(li1->hostname));
	}
	إذا (be_verbose)
		dump_logininfo(li1, "li1");

	إذا ((صحيح)geteuid() != 0) {
		لکو("NOT RUNNING LOGIN TESTS - you are not root!\n");
		أرجع 1;
	}

	إذا (nologtest)
		أرجع 1;

	سٽ_stripname(stripline, li1->سٽ, حجم(stripline));

	لکو("Performing an invalid login attempt (no type field)\n--\n");
	login_write(li1);
	لکو("--\n(Should have written errors to stderr)\n");

#جيڪڏهن_وصف_ٿيل HAVE_وقت_H
	(فراغ)time(&t0);
	strlcpy(s_t0, ctime(&t0), حجم(s_t0));
	t1 = login_get_lastlog_وقت(getuid());
	strlcpy(s_t1, ctime(&t1), حجم(s_t1));
	لکو("Before logging in:\n\tcurrent time is %d - %s\t"
	    "lastlog time is %d - %s\n",
	    (صحيح)t0, s_t0, (صحيح)t1, s_t1);
#جيڪڏهن_پورو

	لکو("Performing a login on line %s ", stripline);
#جيڪڏهن_وصف_ٿيل HAVE_وقت_H
	(فراغ)time(&logintime);
	strlcpy(s_logintime, ctime(&logintime), حجم(s_logintime));
	لکو("at %d - %s", (صحيح)logintime, s_logintime);
#جيڪڏهن_پورو
	لکو("--\n");
	login_login(li1);

	snprintf(cmdstring, حجم(cmdstring), "who | grep '%s '",
		 stripline);
	system(cmdstring);

	لکو("--\nPausing for %d second(s)...\n", PAUSE_BEFORE_LOGOUT);
	sleep(PAUSE_BEFORE_LOGOUT);

	لکو("Performing a logout ");
#جيڪڏهن_وصف_ٿيل HAVE_وقت_H
	(فراغ)time(&logouttime);
	strlcpy(s_logouttime, ctime(&logouttime), حجم(s_logouttime));
	لکو("at %d - %s", (صحيح)logouttime, s_logouttime);
#جيڪڏهن_پورو
	لکو("\nThe root login shown above should be gone.\n"
	    "If the root login hasn't gone, but another user on the same\n"
	    "pty has, this is OK - we're hacking it here, and there\n"
	    "shouldn't be two users on one pty in reality...\n"
	    "-- ('who' output follows)\n");
	login_logout(li1);

	system(cmdstring);
	لکو("-- ('who' output ends)\n");

#جيڪڏهن_وصف_ٿيل HAVE_وقت_H
	t2 = login_get_lastlog_وقت(getuid());
	strlcpy(s_t2, ctime(&t2), حجم(s_t2));
	لکو("After logging in, lastlog time is %d - %s\n", (صحيح)t2, s_t2);
	إذا (t1 == t2)
		لکو("The lastlog times before and after logging in are the "
		    "same.\nThis indicates that lastlog is ** NOT WORKING "
		    "CORRECTLY **\n");
	وإلا إذا (t0 != t2)
		/* We can be off by a second or so, even when recording works fine.
		 * I'm not 100% sure why, but it's true. */
		لکو("** The login time and the lastlog time differ.\n"
		    "** This indicates that lastlog is either recording the "
		    "wrong time,\n** or retrieving the wrong entry.\n"
		    "If it's off by less than %d second(s) "
		    "run the test again.\n", PAUSE_BEFORE_LOGOUT);
	وإلا
		لکو("lastlog agrees with the login time. This is a good thing.\n");

#جيڪڏهن_پورو

	لکو("--\nThe output of 'last' shown next should have "
	    "an entry for root \n  on %s for the time shown above:\n--\n",
	    stripline);
	snprintf(cmdstring, حجم(cmdstring), "last | grep '%s ' | head -3",
		 stripline);
	system(cmdstring);

	لکو("--\nEnd of login test.\n");

	login_free_داخلا(li1);

	أرجع 1;
} /* testAPI() */


فراغ
test_سٽ_Name(حرف *سٽ)
{
	/* have to null-terminate - these functions are designed for
	 * structures with fixed-length char arrays, and don't null-term.*/
	حرف ڀريل[17], strip[9], abbrev[5];

	memset(ڀريل, '\0', حجم(ڀريل));
	memset(strip, '\0', حجم(strip));
	memset(abbrev, '\0', حجم(abbrev));

	سٽ_fullname(ڀريل, سٽ, حجم(ڀريل)-1);
	سٽ_stripname(strip, ڀريل, حجم(strip)-1);
	سٽ_abbrevname(abbrev, ڀريل, حجم(abbrev)-1);
	لکو("%s: %s, %s, %s\n", سٽ, ڀريل, strip, abbrev);

} /* testLineName() */


صحيح
testOutput()
{
	لکو("**\n** Testing linename functions\n**\n");
	test_سٽ_Name("/dev/pts/1");
	test_سٽ_Name("pts/1");
	test_سٽ_Name("pts/999");
	test_سٽ_Name("/dev/ttyp00");
	test_سٽ_Name("ttyp00");

	أرجع 1;
} /* testOutput() */


/* show which options got compiled in */
فراغ
showOptions(فراغ)
{
	لکو("**\n** Compile-time options\n**\n");

	لکو("login recording methods selected:\n");
#جيڪڏهن_وصف_ٿيل USE_LOGIN
	لکو("\tUSE_LOGIN\n");
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل USE_UTMP
	لکو("\tUSE_UTMP (UTMP_FILE=%s)\n", UTMP_FILE);
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل USE_UTMPX
	لکو("\tUSE_UTMPX\n");
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل USE_WTMP
	لکو("\tUSE_WTMP (WTMP_FILE=%s)\n", WTMP_FILE);
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل USE_WTMPX
	لکو("\tUSE_WTMPX (WTMPX_FILE=%s)\n", WTMPX_FILE);
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل USE_LASTLOG
	لکو("\tUSE_LASTLOG (LASTLOG_FILE=%s)\n", LASTLOG_FILE);
#جيڪڏهن_پورو
	لکو("\n");

} /* showOptions() */


صحيح
مکيه(صحيح argc, حرف *argv[])
{
	لکو("Platform-independent login recording test driver\n");

	__progname = ssh_get_progname(argv[0]);
	إذا (argc == 2) {
		إذا (لڙي_ڀيٽ(argv[1], "-i", 3) == 0)
			compile_opts_only = 1;
		وإلا إذا (لڙي_ڀيٽ(argv[1], "-v", 3) == 0)
			be_verbose=1;
	}

	إذا (!compile_opts_only) {
		إذا (be_verbose && !testOutput())
			أرجع 1;

		إذا (!testAPI())
			أرجع 1;
	}

	showOptions();

	أرجع 0;
} /* main() */

